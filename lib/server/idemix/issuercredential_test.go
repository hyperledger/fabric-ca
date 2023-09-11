/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/IBM/idemix/bccsp/types"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestLoadEmptyIdemixPublicKey(t *testing.T) {
	_, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	pubkeyfile, err := os.CreateTemp(testdir, "IdemixPublicKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	ic := NewIssuerCredential(pubkeyfile.Name(), testSecretKeyFile, getCSP(t))
	err = ic.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Issuer public key file is empty")
	}
}

func TestLoadFakeIdemixPublicKey(t *testing.T) {
	testdir := t.TempDir()
	pubkeyfile, err := os.CreateTemp(testdir, "IdemixPublicKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	privkeyfile, err := os.CreateTemp(testdir, "IdemixSecretKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	_, err = pubkeyfile.WriteString("foo")
	if err != nil {
		t.Fatalf("Failed to write to the file %s", pubkeyfile.Name())
	}
	ik := NewIssuerCredential(pubkeyfile.Name(), privkeyfile.Name(), getCSP(t))
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to import Issuer key")
	}
}

func TestLoadEmptyIdemixSecretKey(t *testing.T) {
	testPublicKeyFile, _, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	privkeyfile, err := os.CreateTemp(testdir, "IdemixSecretKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	ik := NewIssuerCredential(testPublicKeyFile, privkeyfile.Name(), getCSP(t))
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Issuer secret key file is empty")
	}
}

func TestLoadNonExistentIdemixSecretKey(t *testing.T) {
	testPublicKeyFile, _, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	ik := NewIssuerCredential(testPublicKeyFile, filepath.Join(testdir, "IdemixSecretKey"), getCSP(t))
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to read Issuer secret key")
	}
}

func TestLoad(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, getCSP(t))
	err = ik.Load()
	assert.NoError(t, err, "Failed to load Idemix issuer credential")

	err = ik.Store()
	assert.NoError(t, err, "Failed to store Idemix issuer credential")
}

func TestStoreNilIssuerKey(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, getCSP(t))
	err = ik.Store()
	assert.Error(t, err, "Should fail if store is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "Issuer credential is not set")
	}
}

func TestStoreNilIdemixPublicKey(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, getCSP(t))
	mockSKey := new(mocks.BccspKey)
	mockPKey := new(mocks.BccspKey)
	mockPKey.On("Bytes").Return(nil, errors.New("bad bad"))
	mockSKey.On("Bytes").Return(nil, errors.New("bad bad"))
	mockSKey.On("PublicKey").Return(mockPKey, nil)
	ik.SetIssuerKey(mockSKey)
	err = ik.Store()
	assert.Error(t, err, "Should fail if store is called with empty issuer public key byte array")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to convert Issuer private key to bytes")
	}
}

func TestStoreReadonlyPublicKeyFilePath(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	pubkeyfile := path.Join(testdir, "testdata1/IdemixPublicKey")

	// Valid issuer public key
	validPubKeyFile := testPublicKeyFile
	pubKeyBytes, err := os.ReadFile(validPubKeyFile)
	if err != nil {
		t.Fatalf("Failed to read idemix public key file %s", validPubKeyFile)
	}

	ipk, err := getCSP(t).KeyImport(pubKeyBytes, &types.IdemixIssuerPublicKeyImportOpts{Temporary: true})
	assert.NoError(t, err)

	err = os.MkdirAll(path.Dir(pubkeyfile), 4444)
	if err != nil {
		t.Fatalf("Failed to create read only directory: %s", err.Error())
	}
	ik := NewIssuerCredential(pubkeyfile, testSecretKeyFile, getCSP(t))
	ik.SetIssuerKey(ipk)
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer public key is being stored to readonly directory")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to store Issuer public key")
	}
}

func TestStoreReadonlySecretKeyFilePath(t *testing.T) {
	testPublicKeyFile, _, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	// foo directory is non-existent
	privkeyfile := filepath.Join(testdir, "foo/IdemixSecretKey")

	// Valid issuer public key
	pubKeyBytes, err := os.ReadFile(testPublicKeyFile)
	if err != nil {
		t.Fatalf("Failed to read idemix public key file %s", testPublicKeyFile)
	}

	ipk, err := getCSP(t).KeyImport(pubKeyBytes, &types.IdemixIssuerPublicKeyImportOpts{Temporary: true})
	assert.NoError(t, err)

	err = os.MkdirAll(path.Dir(privkeyfile), 4444)
	if err != nil {
		t.Fatalf("Failed to create read only directory: %s", err.Error())
	}
	ik := NewIssuerCredential(testPublicKeyFile, privkeyfile, getCSP(t))
	ik.SetIssuerKey(ipk)
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer secret key is being stored to read-only directory")
	if err != nil {
		assert.Equal(t, "Failed to store Issuer secret key", err.Error())
	}
}

func TestGetIssuerKey(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, getCSP(t))
	_, err = ik.GetIssuerKey()
	assert.Error(t, err, "GetIssuerKey should return an error if it is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "Issuer credential is not set")
	}
	err = ik.Load()
	if err != nil {
		t.Fatalf("Load of valid issuer public and secret key should not fail: %s", err)
	}
	_, err = ik.GetIssuerKey()
	assert.NoError(t, err, "GetIssuerKey should not return an error if the issuer key is set")
}

func TestNewIssuerKeyError(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mockCsp := new(mocks.BccspBCCSP)
	mockCsp.On("KeyGen", &types.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: []string{"OU", "Role", "EnrollmentID", "RevocationHandle"}}).Return(nil, errors.New("ajajaja"))

	ic := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, mockCsp)
	_, err = ic.NewIssuerKey()
	assert.Error(t, err)
}

func TestNewIssuerKey(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ic := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, getCSP(t))
	_, err = ic.NewIssuerKey()
	assert.NoError(t, err)
}
