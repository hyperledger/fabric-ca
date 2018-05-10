/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"bytes"
	"crypto/ecdsa"
	"testing"

	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	dmocks "github.com/hyperledger/fabric-ca/lib/dbutil/mocks"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestGetRAInfoFromDBError(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	rainfos := []RevocationAuthorityInfo{}
	db := new(dmocks.FabricCADB)
	db.On("Select", &rainfos, "SELECT * FROM revocation_authority_info").
		Return(errors.New("Failed to execute select query"))
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetRAInfoFromNewDBSelectError(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")

	db := new(dmocks.FabricCADB)
	raInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, nil, true, true, false)
	db.On("Select", &raInfos, SelectRAInfo).Return(f)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetRAInfoFromExistingDB(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")

	db := new(dmocks.FabricCADB)
	raInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, nil, false, false, false)
	db.On("Select", &raInfos, SelectRAInfo).Return(f)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.NoError(t, err)
}

func TestGetRAInfoFromExistingDBBadKey(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")

	db := new(dmocks.FabricCADB)
	raInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, nil, false, false, true)
	db.On("Select", &raInfos, SelectRAInfo).Return(f)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetRAInfoFromNewDBInsertFailure(t *testing.T) {
	issuer, db, pk := setupForInsertTests(t)
	pkStr, pubStr, err := EncodeKeys(pk, &pk.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encode revocation authority long term key: %s", err.Error())
	}
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
		PrivateKey:           pkStr,
		PublicKey:            pubStr,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(0), nil)
	db.On("NamedExec", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to insert the revocation authority info record; no rows affected")
	}
}

func TestGetRAInfoFromNewDBInsertFailure1(t *testing.T) {
	issuer, db, pk := setupForInsertTests(t)
	pkStr, pubStr, err := EncodeKeys(pk, &pk.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encode revocation authority long term key: %s", err.Error())
	}
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
		PrivateKey:           pkStr,
		PublicKey:            pubStr,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(2), nil)
	db.On("NamedExec", InsertRAInfo, &rainfo).Return(result, nil)
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Expected to affect 1 entry in revocation authority info table but affected")
	}
}

func TestGetRAInfoFromNewDBInsertError(t *testing.T) {
	issuer, db, pk := setupForInsertTests(t)
	pkStr, pubStr, err := EncodeKeys(pk, &pk.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encode revocation authority long term key: %s", err.Error())
	}
	rainfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
		PrivateKey:           pkStr,
		PublicKey:            pubStr,
	}
	db.On("NamedExec", InsertRAInfo, &rainfo).Return(nil,
		errors.New("Inserting revocation authority info into DB failed"))
	issuer.On("DB").Return(db)
	opts := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(opts)
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
}

func TestGetLongTermKeyError(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	lib := new(mocks.Lib)
	lib.On("GenerateLongTermRevocationKey").Return(nil, errors.New("Failed to create long term key for revocation authority"))
	issuer.On("IdemixLib").Return(lib)
	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, nil, true, false, false)
	db.On("Select", &rcInfos, SelectRAInfo).Return(f)
	issuer.On("DB").Return(db)
	_, err := NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to generate long term key")
	}
}

func TestGetLongTermKeyEncodingError(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	lib := new(mocks.Lib)
	privateKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	privateKey.PublicKey = ecdsa.PublicKey{}
	lib.On("GenerateLongTermRevocationKey").Return(privateKey, nil)
	issuer.On("IdemixLib").Return(lib)
	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, nil, true, false, false)
	db.On("Select", &rcInfos, SelectRAInfo).Return(f)
	issuer.On("DB").Return(db)
	_, err = NewRevocationAuthority(issuer, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to encode long term key of the revocation authority")
}
func TestGetNewRevocationHandleSelectError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, db, 0, false, false)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, true, true)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to get revocation authority info from database")
}

func TestGetNewRevocationHandleNoData(t *testing.T) {
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, db, 0, false, false)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, false)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(fnc)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No revocation authority info found in database")
}

func TestGetNewRevocationHandleExecError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, db, 0, false, false)

	tx := new(dmocks.FabricCATx)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(fnc)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to update revocation authority info")
}

func TestGetNewRevocationHandleRollbackError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, db, 0, false, false)

	tx := new(dmocks.FabricCATx)
	rcInfos := []RevocationAuthorityInfo{}
	fnc := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(fnc)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, errors.New("Exec error"))
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(errors.New("Rollback error"))

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error encountered while rolling back transaction")
}

func TestGetNewRevocationHandleCommitError(t *testing.T) {
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, db, 0, false, false)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(errors.New("Error commiting"))
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	_, err := ra.GetNewRevocationHandle()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error encountered while committing transaction")
}

func TestGetNewRevocationHandle(t *testing.T) {
	db := new(dmocks.FabricCADB)
	rc := getRevocationAuthority(t, db, 0, false, false)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextHandle).Return(UpdateNextHandle)
	tx.On("Exec", UpdateNextHandle, 2, 1).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 1, false, true)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	rh, err := rc.GetNewRevocationHandle()
	assert.NoError(t, err)
	assert.Equal(t, 0, bytes.Compare(idemix.BigToBytes(fp256bn.NewBIGint(1)), idemix.BigToBytes(rh)), "Expected next revocation handle to be 1")
}

func TestGetNewRevocationHandleLastHandle(t *testing.T) {
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, db, 0, false, false)

	tx := new(dmocks.FabricCATx)
	tx.On("Commit").Return(nil)
	tx.On("Rollback").Return(nil)
	tx.On("Rebind", SelectRAInfo).Return(SelectRAInfo)
	tx.On("Rebind", UpdateNextAndLastHandle).Return(UpdateNextAndLastHandle)
	tx.On("Exec", UpdateNextAndLastHandle, 101, 200, 2).Return(nil, nil)
	rcInfos := []RevocationAuthorityInfo{}
	f1 := getTxSelectFunc(t, &rcInfos, 100, false, true)
	tx.On("Select", &rcInfos, SelectRAInfo).Return(f1)

	db.On("BeginTx").Return(tx)
	rh, err := ra.GetNewRevocationHandle()
	assert.NoError(t, err)
	assert.Equal(t, 0, bytes.Compare(idemix.BigToBytes(fp256bn.NewBIGint(100)), idemix.BigToBytes(rh)), "Expected next revocation handle to be 100")
	assert.Equal(t, util.B64Encode(idemix.BigToBytes(fp256bn.NewBIGint(100))), util.B64Encode(idemix.BigToBytes(rh)), "Expected next revocation handle to be 100")
}

func TestCreateCRI(t *testing.T) {
	db := new(dmocks.FabricCADB)
	ra := getRevocationAuthority(t, db, 0, true, false)
	_, err := ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if there is an error getting revoked credentials")

	db = new(dmocks.FabricCADB)
	ra = getRevocationAuthority(t, db, 0, false, true)
	_, err = ra.CreateCRI()
	assert.Error(t, err, "CreateCRI should fail if idemix.CreateCRI returns an error")

	db = new(dmocks.FabricCADB)
	ra = getRevocationAuthority(t, db, 0, false, false)
	cri, err := ra.CreateCRI()
	assert.NoError(t, err)

	db = new(dmocks.FabricCADB)
	cri1, err := ra.CreateCRI()
	assert.NoError(t, err)
	assert.Equal(t, cri.Epoch, cri1.Epoch)

	// db = new(dmocks.FabricCADB)
	// ra = getRevocationAuthority(t, db, 1, false, false)
	// _, err = ra.CreateCRI()
	// assert.NoError(t, err)
}

func TestEncodeKeys(t *testing.T) {
	privateKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	pkstr, pubkeystr, err := EncodeKeys(privateKey, &privateKey.PublicKey)
	assert.NoError(t, err)

	_, _, err = DecodeKeys("", pubkeystr)
	assert.Error(t, err)
	assert.Equal(t, "Failed to decode ECDSA private key", err.Error())

	_, _, err = DecodeKeys(pubkeystr, pkstr)
	assert.Error(t, err, "DecodeKeys should fail as encoded public key string is passed as private key")

	_, _, err = DecodeKeys(pkstr, "")
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

func setupForInsertTests(t *testing.T) (*mocks.MyIssuer, *dmocks.FabricCADB, *ecdsa.PrivateKey) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	lib := new(mocks.Lib)
	privateKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	lib.On("GenerateLongTermRevocationKey").Return(privateKey, nil)
	issuer.On("IdemixLib").Return(lib)
	db := new(dmocks.FabricCADB)
	rcInfos := []RevocationAuthorityInfo{}
	f := getSelectFunc(t, nil, true, false, false)
	db.On("Select", &rcInfos, SelectRAInfo).Return(f)
	return issuer, db, privateKey
}

func getRevocationAuthority(t *testing.T, db *dmocks.FabricCADB, revokedCred int,
	getRevokedCredsError bool, idemixCreateCRIError bool) RevocationAuthority {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	lib := new(mocks.Lib)
	privateKey, err := idemix.GenerateLongTermRevocationKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key for revocation authority")
	}
	pkStr, pubStr, err := EncodeKeys(privateKey, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encode revocation authority long term key: %s", err.Error())
	}

	lib.On("GenerateLongTermRevocationKey").Return(privateKey, nil)
	issuer.On("IdemixLib").Return(lib)

	f := getSelectFunc(t, privateKey, true, false, false)

	rcInfosForSelect := []RevocationAuthorityInfo{}
	db.On("Select", &rcInfosForSelect, SelectRAInfo).Return(f)
	rcinfo := RevocationAuthorityInfo{
		Epoch:                1,
		NextRevocationHandle: 1,
		LastHandleInPool:     100,
		Level:                1,
		PrivateKey:           pkStr,
		PublicKey:            pubStr,
	}
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(int64(1), nil)
	db.On("NamedExec", InsertRAInfo, &rcinfo).Return(result, nil)
	issuer.On("DB").Return(db)
	cfg := &Config{RHPoolSize: 100}
	issuer.On("Config").Return(cfg)

	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Failed generate random number: %s", err.Error())
	}
	issuer.On("IdemixRand").Return(rnd)

	credDBAccessor := new(mocks.CredDBAccessor)
	if getRevokedCredsError {
		credDBAccessor.On("GetRevokedCredentials").Return(nil, errors.New("Failed to get revoked credentials"))
	} else {
		revokedCreds := []CredRecord{}
		if revokedCred > 0 {
			rh := util.B64Encode(idemix.BigToBytes(fp256bn.NewBIGint(revokedCred)))
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

	validHandles := []*fp256bn.BIG{}
	for i := 1; i <= 100; i = i + 1 {
		validHandles = append(validHandles, fp256bn.NewBIGint(i))
	}
	alg := idemix.ALG_NO_REVOCATION
	if revokedCred > 0 {
		validHandles = append(validHandles[:revokedCred], validHandles[revokedCred+1:]...)
		alg = idemix.ALG_PLAIN_SIGNATURE
	}
	if idemixCreateCRIError {
		lib.On("CreateCRI", privateKey, validHandles, 1, alg, rnd).Return(nil, errors.New("Idemix lib create CRI error"))
	} else {
		cri, err := idemix.CreateCRI(privateKey, validHandles, 1, alg, rnd)
		if err != nil {
			t.Fatalf("Failed to create CRI: %s", err.Error())
		}
		lib.On("CreateCRI", privateKey, validHandles, 1, alg, rnd).Return(cri, nil)
	}

	ra, err := NewRevocationAuthority(issuer, 1)
	if err != nil {
		t.Fatalf("Failed to get revocation authority instance: %s", err.Error())
	}
	return ra
}

func getSelectFunc(t *testing.T, privateKey *ecdsa.PrivateKey, newDB bool, isError bool, badKey bool) func(interface{}, string, ...interface{}) error {
	numTimesCalled := 0
	return func(dest interface{}, query string, args ...interface{}) error {
		rcInfos, _ := dest.(*[]RevocationAuthorityInfo)
		if privateKey == nil {
			var err error
			privateKey, err = idemix.GenerateLongTermRevocationKey()
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key for revocation authority")
			}
		}
		var err error
		pkStr, pubStr, err := EncodeKeys(privateKey, &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to encode revocation authority long term key: %s", err.Error())
		}
		if badKey {
			pkStr = ""
		}
		rcInfo := RevocationAuthorityInfo{
			Epoch:                1,
			NextRevocationHandle: 1,
			LastHandleInPool:     100,
			Level:                1,
			PrivateKey:           pkStr,
			PublicKey:            pubStr,
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

func getTxSelectFunc(t *testing.T, rcs *[]RevocationAuthorityInfo, nextRH int, isError bool, isAppend bool) func(interface{}, string, ...interface{}) error {
	return func(dest interface{}, query string, args ...interface{}) error {
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
