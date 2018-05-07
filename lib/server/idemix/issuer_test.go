/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/lib/dbutil"

	"github.com/hyperledger/fabric-ca/lib"
	dmocks "github.com/hyperledger/fabric-ca/lib/dbutil/mocks"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewIssuer(t *testing.T) {
	lib := new(mocks.Lib)
	cfg := &Config{
		NonceExpiration:    "15",
		NonceSweepInterval: "15",
	}
	issuer := NewIssuer("ca1", ".", cfg, lib)
	assert.NotNil(t, issuer)
}

func TestInit(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerinittest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)
	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should not return an error if db is nil")

	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	ik, err := issuer.IssuerPublicKey()
	assert.NoError(t, err, "IssuerPublicKey should not return an error")
	assert.NotNil(t, ik)
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("IsBasicAuth").Return(true)
	ctx.On("BasicAuthentication").Return("", errors.New("Authentication error"))
	_, err = issuer.IssueCredential(ctx)
	assert.Error(t, err, "IssuerCredential should fail")
}

func TestInitDBNotInitialized(t *testing.T) {
	cfg := &Config{
		NonceExpiration:    "15s",
		NonceSweepInterval: "15m",
	}
	var db *dmocks.FabricCADB
	issuer := NewIssuer("ca1", ".", cfg, NewLib())
	err := issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)

	db = new(dmocks.FabricCADB)
	db.On("IsInitialized").Return(false)
	issuer = NewIssuer("ca1", ".", cfg, NewLib())
	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)
}

func TestInitExistingIssuerCredential(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerinittest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = lib.CopyFile(testPublicKeyFile, filepath.Join(testdir, "IssuerPublicKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}
	err = lib.CopyFile(testSecretKeyFile, filepath.Join(testdir, "msp/keystore/IssuerSecretKey"))
	if err != nil {
		t.Fatalf("Failed to copy file: %s", err.Error())
	}

	db, issuer := getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	secrekeyfile := filepath.Join(testdir, "msp/keystore/IssuerSecretKey")
	secrekeyFileInfo, err := os.Stat(secrekeyfile)
	if err != nil {
		t.Fatalf("os.Stat failed on test dir: %s", err)
	}
	oldmode := secrekeyFileInfo.Mode()
	err = os.Chmod(secrekeyfile, 0000)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", secrekeyFileInfo.Name(), err)
	}
	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.Error(t, err, "Init should fail if it fails to load issuer credential")

	err = os.Chmod(secrekeyfile, oldmode)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", testdir, err)
	}
	err = issuer.Init(false, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err)
}
func TestInitRenewTrue(t *testing.T) {
	testdir, err := ioutil.TempDir(".", "issuerinittest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	db, issuer := getIssuer(t, testdir, true, false)
	assert.NotNil(t, issuer)

	err = issuer.Init(true, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.Error(t, err, "Init should fail if it fails to generate random number")

	db, issuer = getIssuer(t, testdir, false, true)
	assert.NotNil(t, issuer)
	err = issuer.Init(true, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.Error(t, err, "Init should fail if it fails to create new issuer key")

	db, issuer = getIssuer(t, testdir, false, false)
	assert.NotNil(t, issuer)

	testdataInfo, err := os.Stat(testdir)
	if err != nil {
		t.Fatalf("os.Stat failed on test dir: %s", err)
	}
	oldmode := testdataInfo.Mode()
	err = os.Chmod(testdir, 0000)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", testdataInfo.Name(), err)
	}
	defer func() {
		err = os.Chmod(testdir, oldmode)
		if err != nil {
			t.Fatalf("Chmod on %s failed: %s", testdir, err)
		}
	}()
	err = issuer.Init(true, db, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.Error(t, err, "Init should fail if it fails to store issuer credential")
}

func getIssuer(t *testing.T, testDir string, getranderror, newIssuerKeyerror bool) (*dmocks.FabricCADB, Issuer) {
	err := os.MkdirAll(filepath.Join(testDir, "msp/keystore"), 0777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	db := new(dmocks.FabricCADB)
	ra := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	db.On("IsInitialized").Return(true)
	rh, err := ra.GetNewRevocationHandle()
	assert.NoError(t, err)
	assert.Equal(t, 1, int(*rh))

	lib := new(mocks.Lib)
	rand, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Failed to get random number: %s", err.Error())
	}
	ik, err := idemix.NewIssuerKey(GetAttributeNames(), rand)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %s", err.Error())
	}
	if getranderror {
		lib.On("GetRand").Return(nil, errors.New("Failed to generate random number"))
	} else {
		lib.On("GetRand").Return(rand, nil)
	}

	if newIssuerKeyerror {
		lib.On("NewIssuerKey", GetAttributeNames(), rand).Return(nil, errors.New("Failed to generate new issuer key"))
	} else {
		lib.On("NewIssuerKey", GetAttributeNames(), rand).Return(ik, nil)
	}

	cfg := &Config{
		NonceExpiration:    "15s",
		NonceSweepInterval: "15m",
	}
	issuer := NewIssuer("ca1", testDir, cfg, lib)
	return db, issuer
}
