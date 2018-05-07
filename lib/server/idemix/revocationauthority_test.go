/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"testing"

	dmocks "github.com/hyperledger/fabric-ca/lib/dbutil/mocks"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestGetRCInfoFromDBError(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	rcinfos := []RevocationComponentInfo{}
	db := new(dmocks.FabricCADB)
	db.On("Select", &rcinfos, "SELECT * FROM revocation_authority_info").
		Return(errors.New("Failed to execute select query"))
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetRCInfoFromNewDBSelectError(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")

	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationComponentInfo{}
	f := getSelectFunc(t, true, true)
	db.On("Select", &rcInfos, SelectRCInfo).Return(f)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetRCInfoFromNewDBInsertFailure(t *testing.T) {
	issuer, db := setupForInsertTests(t)
	rcinfo := RevocationComponentInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(0), nil)
	db.On("NamedExec", InsertRCInfo, &rcinfo).Return(result, nil)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to insert the revocation authority info record; no rows affected")
	}
}

func TestGetRCInfoFromNewDBInsertFailure1(t *testing.T) {
	issuer, db := setupForInsertTests(t)
	rcinfo := RevocationComponentInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(2), nil)
	db.On("NamedExec", InsertRCInfo, &rcinfo).Return(result, nil)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Expected to affect 1 entry in revocation authority info table but affected")
	}
}

func TestGetRCInfoFromNewDBInsertError(t *testing.T) {
	issuer, db := setupForInsertTests(t)
	rcinfo := RevocationComponentInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	db.On("NamedExec", InsertRCInfo, &rcinfo).Return(nil,
		errors.New("Inserting revocation authority info into DB failed"))
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetNewRevocationHandleSelectError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, true, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to get revocation authority info from database")
}

func TestGetNewRevocationHandleNoData(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, false)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No revocation authority info found in database")
}

func TestGetNewRevocationHandleExecError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to update revocation authority info")
}

func TestGetNewRevocationHandleRollbackError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	rcInfos := []RevocationComponentInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(fnc)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(errors.New("Rollback error"))

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error encountered while rolling back transaction")
}

func TestGetNewRevocationHandleCommitError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(errors.New("Error commiting"))
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	_, err := rc.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error encountered while committing transaction")
}

func TestGetNewRevocationHandle(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

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
	rh, err := rc.GetNewRevocationHandle()
	assert.NoError(t, err)
	assert.Equal(t, 1, int(*rh))
}

func TestGetNewRevocationHandleLastHandle(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationComponent(t, db)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRCInfo).Return(SelectRCInfo)
	tx.On("Rebind", UpdateNextAndLastHandle).Return(UpdateNextAndLastHandle)
	tx.On("Exec", UpdateNextAndLastHandle, 101, 200, 1).Return(nil, nil)
	rcInfos := []RevocationComponentInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 100, false, true)
	tx.On("Select", &rcInfos, SelectRCInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	rh, err := rc.GetNewRevocationHandle()
	assert.NoError(t, err)
	assert.Equal(t, 100, int(*rh))
}

func setupForInsertTests(t *testing.T) (*mocks.MyIssuer, *dmocks.FabricCADB) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")

	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationComponentInfo{}
	f := getSelectFunc(t, false, false)
	db.On("Select", &rcInfos, SelectRCInfo).Return(f)
	return issuer, db
}

func getRevocationComponent(t *testing.T, db *dmocks.FabricCADB) RevocationAuthority {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")

	f := getSelectFunc(t, true, false)

	rcInfosForSelect := []RevocationComponentInfo{}
	db.On("Select", &rcInfosForSelect, SelectRCInfo).Return(f)
	rcinfo := RevocationComponentInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(1), nil)
	db.On("NamedExec", InsertRCInfo, &rcinfo).Return(result, nil)
	issuer.On("DB").Return(db)
	cfg := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(cfg)
	rc, err := NewRevocationAuthority(issuer, 1)
	if err != nil {
		t.Fatalf("Failed to get revocation authority instance: %s", err.Error())
	}
	return rc
}

func getSelectFunc(t *testing.T, newDB bool, isError bool) func(interface{}, string, ...interface{}) error {
	return func(dest interface{}, query string, args ...interface{}) error {
		rcInfos, _ := dest.(*[]RevocationComponentInfo)
		if !newDB {
			rcInfo := RevocationComponentInfo{
				Epoch:                0,
				NextRevocationHandle: 1,
				LastHandleInPool:     100,
				Level:                1,
			}
			*rcInfos = append(*rcInfos, rcInfo)
		}
		if isError {
			return errors.New("Failed to get RevocationComponentInfo from DB")
		}
		return nil
	}
}

func getTxSelectFunc(t *testing.T, rcs *[]RevocationComponentInfo, nextRH int, isError bool, isAppend bool) func(interface{}, string, ...interface{}) error {
	return func(dest interface{}, query string, args ...interface{}) error {
		rcInfos := dest.(*[]RevocationComponentInfo)
		rcInfo := RevocationComponentInfo{
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
