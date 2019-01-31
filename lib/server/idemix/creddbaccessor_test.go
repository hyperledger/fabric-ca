/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"fmt"
	"testing"
	"time"

	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	dmocks "github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/kisielk/sqlstruct"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestInsertCredentialNilDB(t *testing.T) {
	credRecord := getCredRecord()

	var db *dmocks.FabricCADB
	accessor := NewCredentialAccessor(db, 1)
	err := accessor.InsertCredential(credRecord)
	assert.Error(t, err)
	assert.Equal(t, "Database is not set", err.Error())
}

func TestInsertCredential(t *testing.T) {
	credRecord := getCredRecord()
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(1), nil)
	db := new(dmocks.FabricCADB)
	db.On("NamedExec", "InsertCredential", InsertCredentialSQL, credRecord).Return(result, nil)
	db.On("Rebind", InsertCredentialSQL).Return(InsertCredentialSQL)
	accessor := NewCredentialAccessor(nil, 1)
	accessor.SetDB(db)
	err := accessor.InsertCredential(credRecord)
	assert.NoError(t, err)
}

func TestInsertCredentialNoRowsAffected(t *testing.T) {
	credRecord := getCredRecord()
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(0), nil)
	db := new(dmocks.FabricCADB)
	db.On("NamedExec", "InsertCredential", InsertCredentialSQL, credRecord).Return(result, nil)
	db.On("Rebind", InsertCredentialSQL).Return(InsertCredentialSQL)
	accessor := NewCredentialAccessor(db, 1)
	err := accessor.InsertCredential(credRecord)
	assert.Error(t, err)
	assert.Equal(t, "Failed to insert the credential record; no rows affected", err.Error())
}

func TestInsertCredentialTwoRowsAffected(t *testing.T) {
	credRecord := getCredRecord()
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(2), nil)
	db := new(dmocks.FabricCADB)
	db.On("NamedExec", "InsertCredential", InsertCredentialSQL, credRecord).Return(result, nil)
	db.On("Rebind", InsertCredentialSQL).Return(InsertCredentialSQL)
	accessor := NewCredentialAccessor(db, 1)
	err := accessor.InsertCredential(credRecord)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Expected to affect 1 entry in credentials table but affected")
}

func TestInsertCredentialExecError(t *testing.T) {
	credRecord := getCredRecord()
	db := new(dmocks.FabricCADB)
	db.On("NamedExec", "InsertCredential", InsertCredentialSQL, credRecord).Return(nil, errors.New("Exec error"))
	db.On("Rebind", InsertCredentialSQL).Return(InsertCredentialSQL)
	accessor := NewCredentialAccessor(db, 1)
	err := accessor.InsertCredential(credRecord)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to insert credential into datastore")
}

func TestGetCredentialsByIDNilDB(t *testing.T) {
	var db *dmocks.FabricCADB
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetCredentialsByID("1")
	assert.Error(t, err)
	assert.Equal(t, "Database is not set", err.Error())
}

func TestGetCredentialsByIDSelectError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	db.On("Rebind", SelectCredentialByIDSQL).Return(SelectCredentialByIDSQL)
	crs := []CredRecord{}
	q := fmt.Sprintf(SelectCredentialByIDSQL, sqlstruct.Columns(CredRecord{}))
	f := getCredSelectFunc(t, true)
	db.On("Select", "GetCredentialsByID", &crs, q, "foo").Return(f)
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetCredentialsByID("foo")
	assert.Error(t, err)
}

func TestGetCredentialsByID(t *testing.T) {
	db := new(dmocks.FabricCADB)
	db.On("Rebind", SelectCredentialByIDSQL).Return(SelectCredentialByIDSQL)
	crs := []CredRecord{}
	q := fmt.Sprintf(SelectCredentialByIDSQL, sqlstruct.Columns(CredRecord{}))
	f := getCredSelectFunc(t, false)
	db.On("Select", "GetCredentialsByID", &crs, q, "foo").Return(f)
	accessor := NewCredentialAccessor(db, 1)
	rcrs, err := accessor.GetCredentialsByID("foo")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(rcrs))
}

func TestGetCredentialNilDB(t *testing.T) {
	var db *dmocks.FabricCADB
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetCredential("1")
	assert.Error(t, err)
	assert.Equal(t, "Database is not set", err.Error())
}

func TestGetCredentialSelectError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	db.On("Rebind", SelectCredentialSQL).Return(SelectCredentialSQL)
	cr := CredRecord{}
	q := fmt.Sprintf(SelectCredentialSQL, sqlstruct.Columns(CredRecord{}))
	db.On("Select", "GetCredential", &cr, q, "1").Return(errors.New("Select error"))
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetCredential("1")
	assert.Error(t, err)
}

func TestGetCredential(t *testing.T) {
	db := new(dmocks.FabricCADB)
	db.On("Rebind", SelectCredentialSQL).Return(SelectCredentialSQL)
	cr := CredRecord{}
	q := fmt.Sprintf(SelectCredentialSQL, sqlstruct.Columns(CredRecord{}))
	db.On("Select", "GetCredential", &cr, q, "1").Return(nil)
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetCredential("1")
	assert.NoError(t, err)
}

func TestGetRevokedCredentialsNilDB(t *testing.T) {
	var db *dmocks.FabricCADB
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetRevokedCredentials()
	assert.Error(t, err)
	assert.Equal(t, "Database is not set", err.Error())
}

func TestGetRevokedCredentialsSelectError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	db.On("Rebind", SelectRevokedCredentialSQL).Return(SelectRevokedCredentialSQL)
	q := fmt.Sprintf(SelectRevokedCredentialSQL, sqlstruct.Columns(CredRecord{}))
	cr := []CredRecord{}
	db.On("Select", "GetRevokedCredentials", &cr, q).Return(errors.New("Failed to get revoked credentials"))
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetRevokedCredentials()
	assert.Error(t, err)
}

func TestGetRevokedCredentials(t *testing.T) {
	db := new(dmocks.FabricCADB)
	db.On("Rebind", SelectRevokedCredentialSQL).Return(SelectRevokedCredentialSQL)
	q := fmt.Sprintf(SelectRevokedCredentialSQL, sqlstruct.Columns(CredRecord{}))
	cr := []CredRecord{}
	db.On("Select", "GetRevokedCredentials", &cr, q).Return(nil)
	accessor := NewCredentialAccessor(db, 1)
	_, err := accessor.GetRevokedCredentials()
	assert.NoError(t, err)
}

func getCredSelectFunc(t *testing.T, isError bool) func(string, interface{}, string, ...interface{}) error {
	return func(funcName string, dest interface{}, query string, args ...interface{}) error {
		crs := dest.(*[]CredRecord)
		cr := getCredRecord()
		*crs = append(*crs, cr)
		if isError {
			return errors.New("Failed to get credentials from DB")
		}
		return nil
	}
}

func getCredRecord() CredRecord {
	return CredRecord{
		ID:               "foo",
		CALabel:          "",
		Expiry:           time.Now(),
		Level:            1,
		Reason:           0,
		Status:           "good",
		RevocationHandle: "1",
		Cred:             "blah",
	}
}
