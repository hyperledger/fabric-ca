/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	proto "github.com/golang/protobuf/proto"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	testPublicKeyFile = "../../../testdata/IdemixPublicKey"
	testSecretKeyFile = "../../../testdata/IdemixSecretKey"
)

func TestLoadEmptyIdemixPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	pubkeyfile, err := ioutil.TempFile(testdir, "IdemixPublicKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ic := NewIssuerCredential(pubkeyfile.Name(), testSecretKeyFile, idemixLib)
	err = ic.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Issuer public key file is empty")
	}
}

func TestLoadFakeIdemixPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	pubkeyfile, err := ioutil.TempFile(testdir, "IdemixPublicKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	privkeyfile, err := ioutil.TempFile(testdir, "IdemixSecretKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	_, err = pubkeyfile.WriteString("foo")
	if err != nil {
		t.Fatalf("Failed to write to the file %s", pubkeyfile.Name())
	}
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(pubkeyfile.Name(), privkeyfile.Name(), idemixLib)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to unmarshal Issuer public key bytes")
	}
}

func TestLoadEmptyIdemixSecretKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	privkeyfile, err := ioutil.TempFile(testdir, "IdemixSecretKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, privkeyfile.Name(), idemixLib)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Issuer secret key file is empty")
	}
}

func TestLoadNonExistentIdemixSecretKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, filepath.Join(testdir, "IdemixSecretKey"), idemixLib)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to read Issuer secret key")
	}
}

func TestLoad(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	err := ik.Load()
	assert.NoError(t, err, "Failed to load Idemix issuer credential")

	err = ik.Store()
	assert.NoError(t, err, "Failed to store Idemix issuer credential")
}

func TestStoreNilIssuerKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	err := ik.Store()
	assert.Error(t, err, "Should fail if store is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "Issuer credential is not set")
	}
}

func TestStoreNilIdemixPublicKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	ik.SetIssuerKey(&idemix.IssuerKey{})
	err := ik.Store()
	assert.Error(t, err, "Should fail if store is called with empty issuer public key byte array")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to marshal Issuer public key")
	}
}

func TestStoreReadonlyPublicKeyFilePath(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerpubkeytest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)

	pubkeyfile := path.Join(testdir, "testdata1/IdemixPublicKey")

	// Valid issuer public key
	validPubKeyFile := testPublicKeyFile
	pubKeyBytes, err := ioutil.ReadFile(validPubKeyFile)
	if err != nil {
		t.Fatalf("Failed to read idemix public key file %s", validPubKeyFile)
	}

	pubKey := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		t.Fatalf("Failed to unmarshal idemix public key bytes from %s", validPubKeyFile)
	}
	idemixLib := new(mocks.Lib)
	err = os.MkdirAll(path.Dir(pubkeyfile), 4444)
	if err != nil {
		t.Fatalf("Failed to create read only directory: %s", err.Error())
	}
	ik := NewIssuerCredential(pubkeyfile, testSecretKeyFile, idemixLib)
	ik.SetIssuerKey(&idemix.IssuerKey{Ipk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer public key is being stored to readonly directory")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to store Issuer public key")
	}
}

func TestStoreReadonlySecretKeyFilePath(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeystoreTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)

	// foo directory is non-existent
	privkeyfile := filepath.Join(testdir, "foo/IdemixSecretKey")

	// Valid issuer public key
	pubKeyBytes, err := ioutil.ReadFile(testPublicKeyFile)
	if err != nil {
		t.Fatalf("Failed to read idemix public key file %s", testPublicKeyFile)
	}

	pubKey := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		t.Fatalf("Failed to unmarshal idemix public key bytes from %s", testPublicKeyFile)
	}
	idemixLib := new(mocks.Lib)
	err = os.MkdirAll(path.Dir(privkeyfile), 4444)
	if err != nil {
		t.Fatalf("Failed to create read only directory: %s", err.Error())
	}
	ik := NewIssuerCredential(testPublicKeyFile, privkeyfile, idemixLib)
	ik.SetIssuerKey(&idemix.IssuerKey{Ipk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer secret key is being stored to read-only directory")
	if err != nil {
		assert.Equal(t, "Failed to store Issuer secret key", err.Error())
	}
}

func TestGetIssuerKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	_, err := ik.GetIssuerKey()
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

func TestNewIssuerKeyGetRandError(t *testing.T) {
	idemixLib := new(mocks.Lib)
	idemixLib.On("GetRand").Return(nil, errors.New("Failed to generate random number"))
	ic := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	_, err := ic.NewIssuerKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error creating new issuer key")
}

func TestNewIssuerKeyError(t *testing.T) {
	idemixLib := new(mocks.Lib)
	rnd, err := NewLib().GetRand()
	if err != nil {
		t.Fatalf("Failed to generate a random number: %s", err.Error())
	}
	idemixLib.On("GetRand").Return(rnd, nil)
	idemixLib.On("NewIssuerKey", GetAttributeNames(), rnd).Return(nil, errors.New("Failed to create new issuer key"))
	ic := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	_, err = ic.NewIssuerKey()
	assert.Error(t, err)
}

func TestNewIssuerKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	idemix := NewLib()
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Failed to generate a random number: %s", err.Error())
	}
	attrNames := GetAttributeNames()
	ik, err := idemix.NewIssuerKey(attrNames, rnd)
	if err != nil {
		t.Fatalf("Failed to create new issuer key: %s", err.Error())
	}
	idemixLib.On("GetRand").Return(rnd, nil)
	idemixLib.On("NewIssuerKey", attrNames, rnd).Return(ik, nil)
	ic := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	_, err = ic.NewIssuerKey()
	assert.NoError(t, err)
}
