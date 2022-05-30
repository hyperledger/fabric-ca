/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"os"
	"path"
	"testing"

	idmx "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	math "github.com/IBM/mathlib"
	cidemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	dmocks "github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestLongTermKeyError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testLongTermKeyError(t, curve)
		})
	}
}

func testLongTermKeyError(t *testing.T, curveID cidemix.CurveID) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("HomeDir").Return(".")
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(".", DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join("./msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	lib := new(mocks.Lib)
	lib.On("GenerateLongTermRevocationKey").Return(nil, errors.New("Failed to create revocation key"))
	issuer.On("IdemixLib").Return(lib)
	db := new(dmocks.FabricCADB)
	issuer.On("DB").Return(db)
	_, err := NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to generate revocation key for issuer")
	}
}

func TestRevocationKeyLoadError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testRevocationKeyLoadError(t, curve)
		})
	}
}

func testRevocationKeyLoadError(t *testing.T, curveID cidemix.CurveID) {
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
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("HomeDir").Return(homeDir)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: revocationpubkeyfile,
		RevocationPrivateKeyfile: revocationprivkeyfile,
	}
	issuer.On("Config").Return(opts)
	lib := new(mocks.Lib)
	issuer.On("IdemixLib").Return(lib)
	db := new(dmocks.FabricCADB)
	issuer.On("DB").Return(db)
	_, err = NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to load revocation key for issuer")
	}
}

func TestGetRAInfoFromDBError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetRAInfoFromDBError(t, curve)
		})
	}
}

func testGetRAInfoFromDBError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("ca1")
	lib := new(mocks.Lib)
	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate test revocation key: %s", err.Error())
	}
	lib.On("GenerateLongTermRevocationKey").Return(revocationKey, nil)
	issuer.On("IdemixLib").Return(lib)
	rainfos := []RevocationAuthorityInfo{}
	db := new(dmocks.FabricCADB)
	db.On("Select", "GetRAInfo", &rainfos, "SELECT * FROM revocation_authority_info").
		Return(errors.New("Failed to execute select query"))
	issuer.On("DB").Return(db)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
}

func TestGetRAInfoFromNewDBSelectError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetRAInfoFromNewDBSelectError(t, curve)
		})
	}
}

func testGetRAInfoFromNewDBSelectError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("HomeDir").Return(homeDir)
	lib := new(mocks.Lib)
	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate test revocation key: %s", err.Error())
	}
	lib.On("GenerateLongTermRevocationKey").Return(revocationKey, nil)
	issuer.On("IdemixLib").Return(lib)
	db := new(dmocks.FabricCADB)
	raInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, true, true)
	db.On("Select", "GetRAInfo", &raInfos, SelectRAInfo).Return(f)
	issuer.On("DB").Return(db)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
}

func TestGetRAInfoFromExistingDB(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetRAInfoFromExistingDB(t, curve)
		})
	}
}

func testGetRAInfoFromExistingDB(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	err := os.MkdirAll(path.Join(homeDir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("HomeDir").Return(homeDir)
	lib := new(mocks.Lib)
	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate test revocation key: %s", err.Error())
	}
	issuer.On("IdemixLib").Return(lib)
	rk := NewRevocationKey(path.Join(homeDir, DefaultRevocationPublicKeyFile),
		path.Join(homeDir, "msp/keystore/", DefaultRevocationPrivateKeyFile), lib)
	rk.SetKey(revocationKey)
	err = rk.Store()
	if err != nil {
		t.Fatalf("Failed to store test revocation key: %s", err.Error())
	}
	db := new(dmocks.FabricCADB)
	raInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, false, false)
	db.On("Select", "GetRAInfo", &raInfos, SelectRAInfo).Return(f)
	issuer.On("DB").Return(db)
	opts := &Config{
		RHPoolSize:               100,
		RevocationPublicKeyfile:  path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1, curveID)
	assert.NoError(t, err)
}

func TestRevocationKeyStoreFailure(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testRevocationKeyStoreFailure(t, curve)
		})
	}
}

func testRevocationKeyStoreFailure(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	issuer, db, _ := setupForInsertTests(t, homeDir)
	os.RemoveAll(path.Join(homeDir, "msp/keystore"))
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(1), nil)
	db.On("NamedExec", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.On("DB").Return(db)
	keystoreDir := path.Join(homeDir, "msp/keystore")
	err := os.MkdirAll(keystoreDir, 4444)
	if err != nil {
		t.Fatalf("Failed to create read only directory: %s", err.Error())
	}
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(keystoreDir, DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to store revocation key of issuer")
	}
}

func TestGetRAInfoFromNewDBInsertFailure(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetRAInfoFromNewDBInsertFailure(t, curve)
		})
	}
}

func testGetRAInfoFromNewDBInsertFailure(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	issuer, db, _ := setupForInsertTests(t, homeDir)
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(0), nil)
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.On("DB").Return(db)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to insert the revocation authority info record; no rows affected")
	}
}

func TestGetRAInfoFromNewDBInsertFailure1(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetRAInfoFromNewDBInsertFailure1(t, curve)
		})
	}
}

func testGetRAInfoFromNewDBInsertFailure1(t *testing.T, curveID cidemix.CurveID) {
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
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(2), nil)
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.On("DB").Return(db)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Expected to affect 1 entry in revocation authority info table but affected")
	}
}

func TestGetRAInfoFromNewDBInsertError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetRAInfoFromNewDBInsertError(t, curve)
		})
	}
}

func testGetRAInfoFromNewDBInsertError(t *testing.T, curveID cidemix.CurveID) {
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
	issuer.On("DB").Return(db)
	opts := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1, curveID)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to insert revocation authority info into database")
	}
}

func TestGetNewRevocationHandleSelectError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetNewRevocationHandleSelectError(t, curve)
		})
	}
}

func testGetNewRevocationHandleSelectError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetNextRevocationHandle", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	tx := new(dmocks.FabricCATx)
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
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetNewRevocationHandleNoData(t, curve)
		})
	}
}

func testGetNewRevocationHandleNoData(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	tx := new(dmocks.FabricCATx)
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
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetNewRevocationHandleExecError(t, curve)
		})
	}
}

func testGetNewRevocationHandleExecError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	tx := new(dmocks.FabricCATx)
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
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetNewRevocationHandleRollbackError(t, curve)
		})
	}
}

func testGetNewRevocationHandleRollbackError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	tx := new(dmocks.FabricCATx)
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
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetNewRevocationHandleCommitError(t, curve)
		})
	}
}

func testGetNewRevocationHandleCommitError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	tx := new(dmocks.FabricCATx)
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
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetNewRevocationHandle(t, curve)
		})
	}
}

func testGetNewRevocationHandle(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	rc := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	tx := new(dmocks.FabricCATx)
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

	curve := cidemix.CurveByID(curveID)

	assert.Equal(t, 0, bytes.Compare(curve.NewZrFromInt(1).Bytes(), rh.Bytes()), "Expected next revocation handle to be 1")
}

func TestGetNewRevocationHandleLastHandle(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetNewRevocationHandleLastHandle(t, curve)
		})
	}
}

func testGetNewRevocationHandleLastHandle(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	tx := new(dmocks.FabricCATx)
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

	curve := cidemix.CurveByID(curveID)
	assert.Equal(t, 0, bytes.Compare(curve.NewZrFromInt(100).Bytes(), rh.Bytes()),
		"Expected next revocation handle to be 100")
	assert.Equal(t, util.B64Encode(curve.NewZrFromInt(100).Bytes()), util.B64Encode(rh.Bytes()),
		"Expected next revocation handle to be 100")
}

func TestGetEpoch(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetEpoch(t, curve)
		})
	}
}

func testGetEpoch(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFunc(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, nil, 0, false, false, curveID, selectFnc)

	rcInfos := []RevocationAuthorityInfo{}
	db.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(selectFnc)
	epoch, err := ra.Epoch()
	assert.NoError(t, err)
	assert.Equal(t, 1, epoch)
	key := ra.PublicKey()
	assert.NotNil(t, key, "Public key should not be nil")
}

func TestGetEpochRAInfoError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetEpochRAInfoError(t, curve)
		})
	}
}

func testGetEpochRAInfoError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)

	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	selectFnc := getSelectFuncForCreateCRI(t, true, true)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, false, curveID, selectFnc)
	_, err = ra.Epoch()
	assert.Error(t, err, "Epoch should fail if there is an error getting revocation info from DB")
}

func TestCreateCRIGetRAInfoError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testCreateCRIGetRAInfoError(t, curve)
		})
	}
}

func testCreateCRIGetRAInfoError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)

	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	selectFnc := getSelectFuncForCreateCRI(t, true, true)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, false, curveID, selectFnc)
	_, err = ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if there is an error getting revocation info from DB")
}

func TestCreateCRIGetRevokeCredsError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testCreateCRIGetRevokeCredsError(t, curve)
		})
	}
}

func testCreateCRIGetRevokeCredsError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	db := new(dmocks.FabricCADB)

	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}

	selectFnc := getSelectFuncForCreateCRI(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, true, false, curveID, selectFnc)
	_, err = ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if there is an error getting revoked credentials")
}

func TestIdemixCreateCRIError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testIdemixCreateCRIError(t, curve)
		})
	}
}

func testIdemixCreateCRIError(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()

	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}

	db := new(dmocks.FabricCADB)
	selectFnc := getSelectFuncForCreateCRI(t, true, false)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, true, curveID, selectFnc)
	_, err = ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if idemix.CreateCRI returns an error")
}

func TestEpochValuesInCRI(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testEpochValuesInCRI(t, curve)
		})
	}
}

func testEpochValuesInCRI(t *testing.T, curveID cidemix.CurveID) {
	homeDir := t.TempDir()
	revocationKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	selectFnc := getSelectFuncForCreateCRI(t, true, false)
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, "GetRAInfo", homeDir, db, revocationKey, 0, false, false, curveID, selectFnc)
	cri, err := ra.CreateCRI()
	assert.NoError(t, err)

	cri1, err := ra.CreateCRI()
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, cri.Epoch, cri1.Epoch)
	}
}

func setupForInsertTests(t *testing.T, homeDir string) (*mocks.MyIssuer, *dmocks.FabricCADB, *ecdsa.PrivateKey) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("HomeDir").Return(homeDir)
	keystore := path.Join(homeDir, "msp/keystore")
	err := os.MkdirAll(keystore, 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory %s: %s", keystore, err.Error())
	}
	lib := new(mocks.Lib)
	privateKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	lib.On("GenerateLongTermRevocationKey").Return(privateKey, nil)
	issuer.On("IdemixLib").Return(lib)
	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, true, false)
	db.On("Select", "GetRAInfo", &rcInfos, SelectRAInfo).Return(f)
	return issuer, db, privateKey
}

func getRevocationAuthority(t *testing.T, funcName, homeDir string, db *dmocks.FabricCADB, revocationKey *ecdsa.PrivateKey, revokedCred int,
	getRevokedCredsError bool, idemixCreateCRIError bool, curveID cidemix.CurveID, selectFnc func(string, interface{}, string, ...interface{}) error) RevocationAuthority {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("ca1")
	issuer.On("HomeDir").Return(homeDir)
	keystore := path.Join(homeDir, "msp/keystore")
	err := os.MkdirAll(keystore, 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory %s: %s", keystore, err.Error())
	}

	if revocationKey == nil {
		var err error
		revocationKey, err = idemix.GenerateLongTermRevocationKey()
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key for revocation authority")
		}
	}
	lib := new(mocks.Lib)
	lib.On("GenerateLongTermRevocationKey").Return(revocationKey, nil)
	issuer.On("IdemixLib").Return(lib)

	rcInfosForSelect := []RevocationAuthorityInfo{}
	db.On("Select", "GetRAInfo", &rcInfosForSelect, SelectRAInfo).Return(selectFnc)
	rcinfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(1), nil)
	db.On("NamedExec", "AddRAInfo", InsertRAInfo, &rcinfo).Return(result, nil)
	issuer.On("DB").Return(db)
	cfg := &Config{
		RHPoolSize: 100, RevocationPublicKeyfile: path.Join(homeDir, DefaultRevocationPublicKeyFile),
		RevocationPrivateKeyfile: path.Join(homeDir, "msp/keystore", DefaultRevocationPrivateKeyFile),
	}
	issuer.On("Config").Return(cfg)

	curve := cidemix.CurveByID(curveID)

	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Failed generate random number: %s", err.Error())
	}
	issuer.On("IdemixRand").Return(rand)

	credDBAccessor := new(mocks.CredDBAccessor)
	if getRevokedCredsError {
		credDBAccessor.On("GetRevokedCredentials").Return(nil, errors.New("Failed to get revoked credentials"))
	} else {
		revokedCreds := []CredRecord{}
		if revokedCred > 0 {
			rh := util.B64Encode(curve.NewZrFromInt(int64(revokedCred)).Bytes())
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

	issuer.On("CredDBAccessor").Return(credDBAccessor)

	idemix := cidemix.InstanceForCurve(curveID)

	var validHandles []*math.Zr
	for i := 1; i <= 100; i = i + 1 {
		validHandles = append(validHandles, curve.NewZrFromInt(int64(i)))
	}
	alg := idmx.ALG_NO_REVOCATION
	if idemixCreateCRIError {
		lib.On("CreateCRI", revocationKey, validHandles, 1, alg).Return(nil, errors.New("Idemix lib create CRI error"))
	} else {
		cri, err := idemix.CreateCRI(revocationKey, validHandles, 1, alg, rand, idemix.Translator)
		if err != nil {
			t.Fatalf("Failed to create CRI: %s", err.Error())
		}
		lib.On("CreateCRI", revocationKey, validHandles, 1, alg).Return(cri, nil)
	}

	ra, err := NewRevocationAuthority(issuer, 1, curveID)
	if err != nil {
		t.Fatalf("Failed to get revocation authority instance: %s", err.Error())
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
