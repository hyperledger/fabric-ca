/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	proto "github.com/golang/protobuf/proto"
	cidemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestLoadEmptyIdemixPublicKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testLoadEmptyIdemixPublicKey(t, curve)
		})
	}
}

func testLoadEmptyIdemixPublicKey(t *testing.T, curveID cidemix.CurveID) {
	_, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	pubkeyfile, err := ioutil.TempFile(testdir, "IdemixPublicKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ic := NewIssuerCredential(pubkeyfile.Name(), testSecretKeyFile, idemixLib, curveID)
	err = ic.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Issuer public key file is empty")
	}
}

func TestLoadFakeIdemixPublicKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testLoadFakeIdemixPublicKey(t, curve)
		})
	}
}

func testLoadFakeIdemixPublicKey(t *testing.T, curveID cidemix.CurveID) {
	testdir := t.TempDir()
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
	ik := NewIssuerCredential(pubkeyfile.Name(), privkeyfile.Name(), idemixLib, curveID)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to unmarshal Issuer public key bytes")
	}
}

func TestLoadEmptyIdemixSecretKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testLoadEmptyIdemixSecretKey(t, curve)
		})
	}
}

func testLoadEmptyIdemixSecretKey(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, _, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	privkeyfile, err := ioutil.TempFile(testdir, "IdemixSecretKey")
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, privkeyfile.Name(), idemixLib, curveID)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Issuer secret key file is empty")
	}
}

func TestLoadNonExistentIdemixSecretKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testLoadNonExistentIdemixSecretKey(t, curve)
		})
	}
}

func testLoadNonExistentIdemixSecretKey(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, _, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, filepath.Join(testdir, "IdemixSecretKey"), idemixLib, curveID)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to read Issuer secret key")
	}
}

func TestLoad(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testLoad(t, curve)
		})
	}
}

func testLoad(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib, curveID)
	err = ik.Load()
	assert.NoError(t, err, "Failed to load Idemix issuer credential")

	err = ik.Store()
	assert.NoError(t, err, "Failed to store Idemix issuer credential")
}

func TestStoreNilIssuerKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testStoreNilIssuerKey(t, curve)
		})
	}
}

func testStoreNilIssuerKey(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib, curveID)
	err = ik.Store()
	assert.Error(t, err, "Should fail if store is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "Issuer credential is not set")
	}
}

func TestStoreNilIdemixPublicKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testStoreNilIdemixPublicKey(t, curve)
		})
	}
}

func testStoreNilIdemixPublicKey(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib, curveID)
	ik.SetIssuerKey(&idemix.IssuerKey{})
	err = ik.Store()
	assert.Error(t, err, "Should fail if store is called with empty issuer public key byte array")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to marshal Issuer public key")
	}
}

func TestStoreReadonlyPublicKeyFilePath(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testStoreReadonlyPublicKeyFilePath(t, curve)
		})
	}
}

func testStoreReadonlyPublicKeyFilePath(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
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
	ik := NewIssuerCredential(pubkeyfile, testSecretKeyFile, idemixLib, curveID)
	ik.SetIssuerKey(&idemix.IssuerKey{Ipk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer public key is being stored to readonly directory")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to store Issuer public key")
	}
}

func TestStoreReadonlySecretKeyFilePath(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testStoreReadonlySecretKeyFilePath(t, curve)
		})
	}
}

func testStoreReadonlySecretKeyFilePath(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, _, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()
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
	ik := NewIssuerCredential(testPublicKeyFile, privkeyfile, idemixLib, curveID)
	ik.SetIssuerKey(&idemix.IssuerKey{Ipk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer secret key is being stored to read-only directory")
	if err != nil {
		assert.Equal(t, "Failed to store Issuer secret key", err.Error())
	}
}

func TestGetIssuerKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetIssuerKey(t, curve)
		})
	}
}

func testGetIssuerKey(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	idemixLib := new(mocks.Lib)
	ik := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib, curveID)
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
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testNewIssuerKeyError(t, curve)
		})
	}
}

func testNewIssuerKeyError(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	idemixLib := new(mocks.Lib)
	rnd, err := cidemix.CurveByID(curveID).Rand()
	if err != nil {
		t.Fatalf("Failed to generate a random number: %s", err.Error())
	}
	idemixLib.On("GetRand").Return(rnd, nil)
	idemixLib.On("NewIssuerKey", GetAttributeNames()).Return(nil, errors.New("Failed to create new issuer key"))
	ic := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib, curveID)
	_, err = ic.NewIssuerKey()
	assert.Error(t, err)
}

func TestNewIssuerKey(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testNewIssuerKey(t, curve)
		})
	}
}

func testNewIssuerKey(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	idemixLib := new(mocks.Lib)
	idemix := NewLib(curveID)
	rnd, err := cidemix.CurveByID(curveID).Rand()
	if err != nil {
		t.Fatalf("Failed to generate a random number: %s", err.Error())
	}
	attrNames := GetAttributeNames()
	ik, err := idemix.NewIssuerKey(attrNames)
	if err != nil {
		t.Fatalf("Failed to create new issuer key: %s", err.Error())
	}
	idemixLib.On("GetRand").Return(rnd, nil)
	idemixLib.On("NewIssuerKey", attrNames).Return(ik, nil)
	ic := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixLib, curveID)
	_, err = ic.NewIssuerKey()
	assert.NoError(t, err)
}
