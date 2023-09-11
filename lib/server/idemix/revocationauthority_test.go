/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"math/big"
	"os"
	"path"
	"testing"

	"github.com/IBM/idemix/bccsp/types"
	bccsp "github.com/IBM/idemix/bccsp/types"
	"github.com/IBM/mathlib/driver/common"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	dmocks "github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLongTermKeyError(t *testing.T) {
	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.HomeDir = "."
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(".", DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join("./msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	db := new(dmocks.DbFabricCADB)
	issuer.Db = db
	mockCsp := new(mocks.BccspBCCSP)
	issuer.Csp = mockCsp
	mockCsp.On("KeyGen", &types.IdemixRevocationKeyGenOpts{Temporary: true}).Return(nil, errors.New("nope"))
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to generate revocation key for issuer")
	}
}

func TestRevocationKeyLoadError(t *testing.T) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	revocationpubkeyfile := path.Join(homeDir, DefaultRevocationPublicKeyFile)
	revocationprivkeyfile := path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile)
	err = util.WriteFile(revocationprivkeyfile, []byte(""), 0o666)
	if err != nil {
		t.Fatalf("Failed to write to file: %s", err.Error())
	}
	err = util.WriteFile(revocationpubkeyfile, []byte(""), 0o666)
	if err != nil {
		t.Fatalf("Failed to write to file: %s", err.Error())
	}
	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.HomeDir = homeDir
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: revocationpubkeyfile,
		RevocationPrivateKeyfile: revocationprivkeyfile,
	}
	issuer.Cfg = opts
	db := new(dmocks.DbFabricCADB)
	issuer.Db = db
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to load revocation key for issuer")
	}
}

func TestGetRAInfoFromDBError(t *testing.T) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := new(IssuerInst)
	issuer.Name = "ca1"
	rainfos := []RevocationAuthorityInfo{}
	db := new(dmocks.DbFabricCADB)
	db.On("Select", "GetRAInfo", &rainfos, "SELECT * FROM revocation_authority_info").
		Return(errors.New("Failed to execute select query"))
	issuer.Db = db
	issuer.Csp = getCSP(t)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetRAInfoFromNewDBSelectError(t *testing.T) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.HomeDir = homeDir
	db := new(dmocks.DbFabricCADB)
	raInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, true, true)
	db.On("Select", "GetRAInfo", &raInfos, SelectRAInfo).Return(f)
	issuer.Db = db
	issuer.Csp = getCSP(t)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetRAInfoFromExistingDB(t *testing.T) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.HomeDir = homeDir
	issuer.Csp = getCSP(t)
	rk := NewRevocationKey(path.Join(homeDir, DefaultRevocationPublicKeyFile),
		path.Join(homeDir, "msp/keystore/", DefaultRevocationPrivateKeyFile), getCSP(t))
	revocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)
	rk.SetKey(revocationKey)
	err = rk.Store()
	if err != nil {
		t.Fatalf("Failed to store test revocation key: %s", err.Error())
	}
	db := new(dmocks.DbFabricCADB)
	raInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, false, false)
	db.On("Select", "GetRAInfo", &raInfos, SelectRAInfo).Return(f)
	issuer.Db = db
	opts := &Config{
		RHPoolSize:               100,
		RevocationPublicKeyfile:  path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	_, err = NewRevocationAuthority(issuer, 1)
	assert.NoError(t, err)
}

func TestRevocationKeyStoreFailure(t *testing.T) {
	homeDir := t.TempDir()
	issuer, db, _ := setupForInsertTests(t, homeDir)
	os.RemoveAll(path.Join(homeDir, "msp/keystore"))
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.SqlResult)
	result.On("RowsAffected").Return(int64(1), nil)
	db.On("NamedExec", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.Db = db
	issuer.Csp = getCSP(t)
	keystoreDir := path.Join(homeDir, "msp/keystore")
	err := os.MkdirAll(keystoreDir, 4444)
	if err != nil {
		t.Fatalf("Failed to create read only directory: %s", err.Error())
	}
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(keystoreDir, DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to store revocation key of issuer")
	}
}

func TestGetRAInfoFromNewDBInsertFailure(t *testing.T) {
	homeDir := t.TempDir()
	issuer, db, _ := setupForInsertTests(t, homeDir)
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.SqlResult)
	result.On("RowsAffected").Return(int64(0), nil)
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.Db = db
	issuer.Csp = getCSP(t)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to insert the revocation authority info record; no rows affected")
	}
}

func TestGetRAInfoFromNewDBInsertFailure1(t *testing.T) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	defer os.RemoveAll(homeDir)
	issuer, db, _ := setupForInsertTests(t, homeDir)
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.SqlResult)
	result.On("RowsAffected").Return(int64(2), nil)
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.Db = db
	issuer.Csp = getCSP(t)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Expected to affect 1 entry in revocation authority info table but affected")
	}
}

func TestGetRAInfoFromNewDBInsertError(t *testing.T) {
	homeDir := t.TempDir()
	issuer, db, _ := setupForInsertTests(t, homeDir)
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rainfo).Return(nil,
		errors.New("Inserting revocation authority info into DB failed"))
	issuer.Db = db
	issuer.Csp = getCSP(t)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = opts
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to insert revocation authority info into database")
	}
}

func TestGetNewRevocationHandleSelectError(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetNextRevocationHandle", homeDir, db, nil, 0, false, false, selectFnc)

	tx := new(dmocks.DbFabricCATx)
	tx.On("Commit", "GetNextRevocationHandle").Return(nil)
	tx.On("Rollback", "GetNextRevocationHandle").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", "GetNextRevocationHandle", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, true, true)
	tx.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(fnc)
	tx.On("Select", "GetNextRevocationHandle", &rcInfos, SelectRAInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to get revocation authority info from database")
	}
}

func TestGetNewRevocationHandleNoData(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, selectFnc)

	tx := new(dmocks.DbFabricCATx)
	tx.On("Commit", "GetNextRevocationHandle").Return(nil)
	tx.On("Rollback", "GetNextRevocationHandle").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", "GetNextRevocationHandle", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, false)
	tx.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "No revocation authority info found in database")
	}
}

func TestGetNewRevocationHandleExecError(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, selectFnc)

	tx := new(dmocks.DbFabricCATx)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(fnc)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", "GetNextRevocationHandle", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit", "GetNextRevocationHandle").Return(nil)
	tx.On("Rollback", "GetNextRevocationHandle").Return(nil)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to update revocation authority info")
	}
}

func TestGetNewRevocationHandleRollbackError(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, selectFnc)

	tx := new(dmocks.DbFabricCATx)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(fnc)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", "GetNextRevocationHandle", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit", "GetNextRevocationHandle").Return(nil)
	tx.On("Rollback", "GetNextRevocationHandle").Return(errors.New("Rollback error"))

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Error encountered while rolling back transaction")
	}
}

func TestGetNewRevocationHandleCommitError(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, selectFnc)

	tx := new(dmocks.DbFabricCATx)
	tx.On("Commit", "GetNextRevocationHandle").Return(errors.New("Error commiting"))
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", "GetNextRevocationHandle", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error encountered while committing transaction")
}

func TestGetNewRevocationHandle(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	rc := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, selectFnc)

	tx := new(dmocks.DbFabricCATx)
	tx.On("Commit", "GetNextRevocationHandle").Return(nil)
	tx.On("Rollback", "GetNextRevocationHandle").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", "GetNextRevocationHandle", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	rh, err := rc.GetNewRevocationHandle()
	assert.NoError(t, err)

	assert.Equal(t, int64(1), rh, "Expected next revocation handle to be 1")
}

func TestGetNewRevocationHandleLastHandle(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, selectFnc)

	tx := new(dmocks.DbFabricCATx)
	tx.On("Commit", "GetNextRevocationHandle").Return(nil)
	tx.On("Rollback", "GetNextRevocationHandle").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextAndLastHandle).Return(UpdateNextAndLastHandle)
	tx.On("Exec", "GetNextRevocationHandle", UpdateNextAndLastHandle, 101, 200, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 100, false, true)
	tx.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	rh, err := ra.GetNewRevocationHandle()
	assert.NoError(t, err)

	assert.Equal(t, int64(100), rh, "Expected next revocation handle to be 100")
}

func TestGetEpoch(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, selectFnc)

	rcInfos := []RevocationAuthorityInfo{}
	db.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(selectFnc)
	epoch, err := ra.Epoch()
	assert.NoError(t, err)
	assert.Equal(t, 1, epoch)
	key := ra.PublicKey()
	assert.NotNil(t, key, "Public key should not be nil")
}

func TestGetEpochRAInfoError(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)

	revocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	selectFnc := getSelectFuncForCreateCRI(t, true, true)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, false, selectFnc)
	_, err = ra.Epoch()
	assert.Error(t, err, "Epoch should fail if there is an error getting revocation info from DB")
}

func TestCreateCRIGetRAInfoError(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)

	revocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	selectFnc := getSelectFuncForCreateCRI(t, true, true)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, false, selectFnc)
	_, err = ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if there is an error getting revocation info from DB")
}

func TestCreateCRIGetRevokeCredsError(t *testing.T) {
	homeDir := t.TempDir()
	db := new(dmocks.DbFabricCADB)

	revocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	selectFnc := getSelectFuncForCreateCRI(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, true, false, selectFnc)
	_, err = ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if there is an error getting revoked credentials")
}

func TestIdemixCreateCRIError(t *testing.T) {
	homeDir := t.TempDir()

	revocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	db := new(dmocks.DbFabricCADB)
	selectFnc := getSelectFuncForCreateCRI(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, true, selectFnc)
	_, err = ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if idemix.CreateCRI returns an error")
}

func TestEpochValuesInCRI(t *testing.T) {
	homeDir := t.TempDir()
	revocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)
	selectFnc := getSelectFuncForCreateCRI(t, true, false)
	db := new(dmocks.DbFabricCADB)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, false, selectFnc)
	_, err = ra.CreateCRI()
	assert.NoError(t, err)

	_, err = ra.CreateCRI()
	assert.NoError(t, err)
}

func setupForInsertTests(t *testing.T, homeDir string) (*IssuerInst, *dmocks.DbFabricCADB, types.Key) {
	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.HomeDir = homeDir
	keystore := path.Join(homeDir, "msp/keystore")
	err := os.MkdirAll(keystore, 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory %s: %s", keystore, err.Error())
	}

	RevocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	db := new(dmocks.DbFabricCADB)
	rcInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, true, false)
	db.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(f)
	return issuer, db, RevocationKey
}

func getRevocationAuthority(t *testing.T, funcName, homeDir string, db *dmocks.DbFabricCADB, revocationKey types.Key, revokedCred int,
	getRevokedCredsError bool, idemixCreateCRIError bool, selectFnc func(string, interface{}, string, ...interface{}) error) RevocationAuthority {
	issuer := new(IssuerInst)
	issuer.Name = "ca1"
	issuer.HomeDir = homeDir
	keystore := path.Join(homeDir, "msp/keystore")
	err := os.MkdirAll(keystore, 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory %s: %s", keystore, err.Error())
	}

	if revocationKey == nil {
		RevocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
		assert.NoError(t, err)
		revocationKey = RevocationKey
	}

	rcInfosForSelect := []RevocationAuthorityInfo{}
	db.On("Select", "GetRAInfo", &rcInfosForSelect, SelectRAInfo).Return(selectFnc)
	rcinfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.SqlResult)
	result.On("RowsAffected").Return(int64(1), nil)
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rcinfo).Return(result, nil)
	issuer.Db = db
	issuer.Csp = getCSP(t)
	cfg := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.Cfg = cfg

	credDBAccessor := new(mocks.CredDBAccessor)
	if getRevokedCredsError {
		credDBAccessor.On("GetRevokedCredentials").Return(nil, errors.New("Failed to get revoked credentials"))
	} else {
		revokedCreds := []CredRecord{}
		if revokedCred > 0 {
			rh := util.B64Encode(common.BigToBytes(big.NewInt(int64(revokedCred))))
			cr := CredRecord{
				RevocationHandle: rh,
				Cred:             "",
				ID:               "",
				Status:           "revoked",
			}
			revokedCreds = append(revokedCreds, cr)
		}
		credDBAccessor.On("GetRevokedCredentials").Return(revokedCreds, nil)
	}

	issuer.CredDBAccessor = credDBAccessor

	ra, err := NewRevocationAuthority(issuer, 1)
	if err != nil {
		t.Fatalf("Failed to get revocation authority instance: %s", err.Error())
	}

	if idemixCreateCRIError {
		mockCsp := new(mocks.BccspBCCSP)
		mockCsp.On("Sign", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("super bad"))
		issuer.Csp = mockCsp
	}

	return ra
}

func getSelectFunc(t *testing.T, newDB bool, isError bool) func(string, interface{}, string, ...interface{}) error {
	numTimesCalled := 0
	return func(funcName string, dest interface{}, query string, args ...interface{}) error {
		rcInfos, _ := dest.(*[]RevocationAuthorityInfo)
		rcInfo := RevocationAuthorityInfo{
			Epoch:                1,
			NextRevocationHandle: 1,
			LastHandleInPool:     100,
			Level:                1,
		}
		if !newDB || numTimesCalled > 0 {
			*rcInfos = append(*rcInfos, rcInfo)
		}
		if isError {
			return errors.New("Failed to get RevocationComponentInfo from DB")
		}
		numTimesCalled = numTimesCalled + 1
		return nil
	}
}

func getSelectFuncForCreateCRI(t *testing.T, newDB bool, isError bool) func(string, interface{}, string, ...interface{}) error {
	numTimesCalled := 0
	return func(funcName string, dest interface{}, query string, args ...interface{}) error {
		rcInfos, _ := dest.(*[]RevocationAuthorityInfo)
		rcInfo := RevocationAuthorityInfo{
			Epoch:                1,
			NextRevocationHandle: 1,
			LastHandleInPool:     100,
			Level:                1,
		}
		if !newDB || numTimesCalled > 0 {
			*rcInfos = append(*rcInfos, rcInfo)
		}

		var err error
		if isError && numTimesCalled%2 == 1 {
			err = errors.New("Failed to get RevocationComponentInfo from DB")
		}
		numTimesCalled = numTimesCalled + 1
		return err
	}
}

func getTxSelectFunc(t *testing.T, rcs *[]RevocationAuthorityInfo, nextRH int, isError bool, isAppend bool) func(string, interface{}, string, ...interface{}) error {
	return func(funcName string, dest interface{}, query string, args ...interface{}) error {
		rcInfos := dest.(*[]RevocationAuthorityInfo)
		rcInfo := RevocationAuthorityInfo{
			Epoch:                1,
			NextRevocationHandle: nextRH,
			LastHandleInPool:     100,
			Level:                1,
		}
		if isAppend {
			*rcInfos = append(*rcInfos, rcInfo)
			*rcs = append(*rcs, rcInfo)
		}

		if isError {
			return errors.New("Failed to get RevocationComponentInfo from DB")
		}
		return nil
	}
}
