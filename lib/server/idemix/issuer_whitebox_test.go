/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/IBM/idemix/bccsp/types"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestIssuer tests issuer
func TestIssuer(t *testing.T) {
	testdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := &IssuerInst{Name: "ca1", HomeDir: testdir, Cfg: &Config{}, Db: &db.DB{}}
	assert.Nil(t, issuer.IssuerCred, "IssueCredential() should return nil")
	assert.Nil(t, issuer.RevocationAuthority, "RevocationAuthority() should return nil")
	assert.Nil(t, issuer.NonceManager, "NonceManager() should return nil")
	assert.Nil(t, issuer.CredDBAccessor, "CredDBAccessor() should return nil")

	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should return not return an error if db is nil")

	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "IssuerPublicKey should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	_, err = issuer.RevocationPublicKey()
	assert.Error(t, err, "RevocationPublicKey should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	_, err = issuer.IssueCredential(nil)
	assert.Error(t, err, "IssueCredential should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	_, err = issuer.GetCRI(nil)
	assert.Error(t, err, "GetCRI should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	issuer.IsInitialized = true
	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should return not return an error if it is already initialized")
}

func TestIssuerPublicKey(t *testing.T) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()

	defer os.RemoveAll(testdir)
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	issuer := &IssuerInst{
		Name:          "ca1",
		HomeDir:       testdir,
		Cfg:           &Config{IssuerPublicKeyfile: "IssuerPublicKey", IssuerSecretKeyfile: "IssuerSecretKey"},
		Db:            &db.DB{},
		IsInitialized: true,
	}

	isk := new(mocks.BccspKey)
	ipk := new(mocks.BccspKey)
	isk.On("PublicKey").Return(ipk, nil)
	isk.On("Bytes").Return([]byte("isk_Bytes"), nil)
	ipk.On("Bytes").Return(nil, errors.New("barf"))

	mockCsp := new(mocks.BccspBCCSP)
	mockCsp.On("KeyImport", mock.Anything, &types.IdemixIssuerPublicKeyImportOpts{Temporary: true, AttributeNames: []string{"OU", "Role", "EnrollmentID", "RevocationHandle"}}).Return(ipk, nil)
	mockCsp.On("KeyImport", mock.Anything, &types.IdemixIssuerKeyImportOpts{Temporary: true, AttributeNames: []string{"OU", "Role", "EnrollmentID", "RevocationHandle"}}).Return(isk, nil)

	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, mockCsp)
	issuer.IssuerCred = issuerCred
	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "issuer.IssuerCredential() should return an error as issuer credential has not been loaded")

	err = issuer.IssuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential: %s", err.Error())
	}
	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "issuer.IssuerCredential() should return an error as it should fail to marshal issuer public key")
}
