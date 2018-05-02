/*
Copyright IBM Corp. 2018 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package idemix_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"

	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/stretchr/testify/assert"
)

const (
	testPublicKeyFile = "../../../testdata/IdemixPublicKey"
	testSecretKeyFile = "../../../testdata/IdemixSecretKey"
)

func TestLoadEmptyIdemixPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	pubkeyfile, err := ioutil.TempFile(testdir, "IdemixPublicKey")
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ic := NewCAIdemixCredential(pubkeyfile.Name(), testSecretKeyFile, idemixLib)
	err = ic.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "CA's Idemix public key file is empty")
	}
}

func TestLoadFakeIdemixPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	pubkeyfile, err := ioutil.TempFile(testdir, "IdemixPublicKey")
	privkeyfile, err := ioutil.TempFile(testdir, "IdemixSecretKey")
	defer os.RemoveAll(testdir)
	_, err = pubkeyfile.WriteString("foo")
	if err != nil {
		t.Fatalf("Failed to write to the file %s", pubkeyfile.Name())
	}
	idemixLib := new(mocks.Lib)
	ik := NewCAIdemixCredential(pubkeyfile.Name(), privkeyfile.Name(), idemixLib)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to unmarshal CA's Idemix public key bytes")
	}
}

func TestLoadNonExistentIdemixSecretKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	privkeyfile, err := ioutil.TempFile(testdir, "IdemixSecretKey")
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ik := NewCAIdemixCredential(testPublicKeyFile, privkeyfile.Name(), idemixLib)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "CA's Idemix secret key file is empty")
	}
}

func TestLoadEmptyIdemixSecretKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeyloadTest")
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	ik := NewCAIdemixCredential(testPublicKeyFile, filepath.Join(testdir, "IdemixSecretKey"), idemixLib)
	err = ik.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer secret key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to read CA's Idemix secret key")
	}
}

func TestLoad(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewCAIdemixCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	err := ik.Load()
	assert.NoError(t, err, "Failed to load CA's issuer idemix credential")

	err = ik.Store()
	assert.NoError(t, err, "Failed to store CA's issuer idemix credential")
}

func TestStoreNilIssuerKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewCAIdemixCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	err := ik.Store()
	assert.Error(t, err, "Should fail if store is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "CA's Idemix credential is not set")
	}
}

func TestStoreNilIdemixPublicKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewCAIdemixCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	ik.SetIssuerKey(&idemix.IssuerKey{})
	err := ik.Store()
	assert.Error(t, err, "Should fail if store is called with empty issuer public key byte array")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to marshal CA's Idemix public key")
	}
}

func TestStoreInvalidPublicKeyFilePath(t *testing.T) {
	pubkeyfile := "./testdata1/IdemixPublicKey"

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
	ik := NewCAIdemixCredential(pubkeyfile, testSecretKeyFile, idemixLib)
	ik.SetIssuerKey(&idemix.IssuerKey{IPk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer public key is being stored to non-existent directory")
	if err != nil {
		assert.Equal(t, err.Error(), "Failed to store CA's Idemix public key")
	}
}

func TestStoreInvalidSecretKeyFilePath(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerkeystoreTest")
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
	ik := NewCAIdemixCredential(testPublicKeyFile, privkeyfile, idemixLib)
	ik.SetIssuerKey(&idemix.IssuerKey{IPk: pubKey})
	err = ik.Store()
	assert.Error(t, err, "Should fail if issuer secret key is being stored to non-existent directory")
	if err != nil {
		assert.Equal(t, "Failed to store CA's Idemix secret key", err.Error())
	}
}

func TestGetIssuerKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	ik := NewCAIdemixCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	_, err := ik.GetIssuerKey()
	assert.Error(t, err, "GetIssuerKey should return an error if it is called without setting the issuer key or loading the issuer key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "CA's Idemix credential is not set")
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
	ic := NewCAIdemixCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
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
	ic := NewCAIdemixCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
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
	ic := NewCAIdemixCredential(testPublicKeyFile, testSecretKeyFile, idemixLib)
	_, err = ic.NewIssuerKey()
	assert.NoError(t, err)
}
