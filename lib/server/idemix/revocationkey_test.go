/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"crypto/ecdsa"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/stretchr/testify/assert"
)

const (
	testRevocationPublicKeyFile  = "../../../testdata/IdemixRevocationPublicKey"
	testRevocationPrivateKeyFile = "../../../testdata/IdemixRevocationPrivateKey"
)

func TestLoadNonExistentRevocationPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "rkloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(path.Join(testdir, DefaultRevocationPublicKeyFile),
		path.Join(testdir, "msp/keystore", DefaultRevocationPrivateKeyFile), idemixLib)
	err = rk.Load()
	assert.Error(t, err, "Should have failed to load non existent revocation public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to read revocation public key")
	}
}

func TestLoadEmptyRevocationPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "rkloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	pubkeyfile, err := ioutil.TempFile(testdir, DefaultRevocationPublicKeyFile)
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(pubkeyfile.Name(), path.Join(testdir, "msp/keystore", DefaultRevocationPrivateKeyFile), idemixLib)
	err = rk.Load()
	assert.Error(t, err, "Should have failed to load empty revocation public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Revocation public key file is empty")
	}
}

func TestLoadFakeRevocationPublicKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "rkloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	pubkeyfile, err := ioutil.TempFile(testdir, DefaultRevocationPublicKeyFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	privkeyfile, err := ioutil.TempFile(testdir, DefaultRevocationPrivateKeyFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	key, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate test revocation key: %s", err.Error())
	}
	privKey, _, err := EncodeKeys(key, &key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encode test revocation key: %s", err.Error())
	}
	err = util.WriteFile(privkeyfile.Name(), privKey, 0666)
	if err != nil {
		t.Fatalf("Failed to write test revocation private key: %s", err.Error())
	}

	_, err = pubkeyfile.WriteString("foo")
	if err != nil {
		t.Fatalf("Failed to write to the file %s", pubkeyfile.Name())
	}
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(pubkeyfile.Name(), privkeyfile.Name(), idemixLib)
	err = rk.Load()
	assert.Error(t, err, "Should have failed to load non existing revocation public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to decode ECDSA public key")
	}
}

func TestLoadNonExistentRevocationPrivateKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "rkloadtest")
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(testRevocationPublicKeyFile, filepath.Join(testdir, "IdemixRevocationPrivateKey"), idemixLib)
	err = rk.Load()
	assert.Error(t, err, "Should have failed to load non existing issuer revocation private key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to read revocation private key")
	}
}

func TestLoadEmptyRevocationPrivateKey(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "rkloadtest")
	privkeyfile, err := ioutil.TempFile(testdir, "")
	defer os.RemoveAll(testdir)
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(testRevocationPublicKeyFile, privkeyfile.Name(), idemixLib)
	err = rk.Load()
	assert.Error(t, err, "Should have failed to load empty issuer revocation private key")
	if err != nil {
		assert.Contains(t, err.Error(), "Revocation private key file is empty")
	}
}

func TestRevocationKeyLoad(t *testing.T) {
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(testRevocationPublicKeyFile, testRevocationPrivateKeyFile, idemixLib)
	err := rk.Load()
	assert.NoError(t, err, "Failed to load Idemix issuer revocation key")

	err = rk.Store()
	assert.NoError(t, err, "Failed to store Idemix issuer revocation key")
}

func TestStoreNilRevocationKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(testRevocationPublicKeyFile, testRevocationPrivateKeyFile, idemixLib)
	err := rk.Store()
	assert.Error(t, err, "Should fail if store is called without setting or loading the revocation key from disk")
	if err != nil {
		assert.Equal(t, err.Error(), "Revocation key is not set")
	}
}

func TestStoreNilRevocationPublicKey(t *testing.T) {
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(testRevocationPublicKeyFile, testRevocationPrivateKeyFile, idemixLib)
	key, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to create test revocation key: %s", err.Error())
	}
	key.PublicKey = ecdsa.PublicKey{}
	rk.SetKey(key)
	err = rk.Store()
	assert.Error(t, err, "Should fail if store is called with empty revocation public key")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to encode revocation public key")
	}
}

func TestEncodeKeys(t *testing.T) {
	privateKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	pkstr, pubkeystr, err := EncodeKeys(privateKey, &privateKey.PublicKey)
	assert.NoError(t, err)

	_, _, err = DecodeKeys([]byte(""), pubkeystr)
	assert.Error(t, err)
	assert.Equal(t, "Failed to decode ECDSA private key", err.Error())

	_, _, err = DecodeKeys(pubkeystr, pkstr)
	assert.Error(t, err, "DecodeKeys should fail as encoded public key string is passed as private key")

	_, _, err = DecodeKeys(pkstr, []byte(""))
	assert.Error(t, err, "DecodeKeys should fail as empty string is passed for encoded public key string")
	assert.Contains(t, err.Error(), "Failed to decode ECDSA public key")

	_, _, err = DecodeKeys(pkstr, pkstr)
	assert.Error(t, err, "DecodeKeys should fail as encoded private key string is passed as public key")
	assert.Contains(t, err.Error(), "Failed to parse ECDSA public key bytes")

	privateKey1, pubKey, err := DecodeKeys(pkstr, pubkeystr)
	assert.NoError(t, err)
	assert.NotNil(t, privateKey1)
	assert.NotNil(t, pubKey)
}

func TestStoreReadonlyRevocationPublicKeyFilepath(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "rkloadTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)

	privkeyfile, err := ioutil.TempFile(testdir, DefaultRevocationPrivateKeyFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %s", err.Error())
	}
	key, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate test revocation key: %s", err.Error())
	}
	privKey, _, err := EncodeKeys(key, &key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encode test revocation key: %s", err.Error())
	}
	err = util.WriteFile(privkeyfile.Name(), privKey, 0666)
	if err != nil {
		t.Fatalf("Failed to write test revocation private key: %s", err.Error())
	}

	pubkeyfile := path.Join(testdir, "testdata1/RevocationPublicKey")
	err = os.MkdirAll(path.Dir(pubkeyfile), 4444)
	if err != nil {
		t.Fatalf("Failed to create read only directory: %s", err.Error())
	}
	idemixLib := new(mocks.Lib)
	rk := NewRevocationKey(pubkeyfile, privkeyfile.Name(), idemixLib)
	rk.SetKey(key)
	err = rk.Store()
	assert.Error(t, err, "Should fail if issuer public key is being stored to read-only directory")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to store revocation public key")
	}
}
