/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"database/sql"
	"testing"
	"time"

	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	dmocks "github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewNonceManager(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("ca1")
	opts := &Config{
		NonceExpiration:    "15",
		NonceSweepInterval: "15",
	}
	clock := new(mocks.Clock)
	lib := new(mocks.Lib)
	issuer.On("Config").Return(opts)
	issuer.On("IdemixLib").Return(lib)
	_, err := NewNonceManager(issuer, clock, 1)
	assert.Error(t, err, "NewNonceManager should return error if the NonceExpiration config option is not in time.Duration string format")
	assert.Contains(t, err.Error(), "Failed to parse idemix.nonceexpiration config option while initializing Nonce manager for Issuer 'ca1'")

	opts.NonceExpiration = "15s"
	_, err = NewNonceManager(issuer, clock, 1)
	assert.Error(t, err, "NewNonceManager should return error if the NonceSweepInterval config option is not in time.Duration string format")
	assert.Contains(t, err.Error(), "Failed to parse idemix.noncesweepinterval config option while initializing Nonce manager for Issuer 'ca1'")

	opts.NonceSweepInterval = "15m"
	_, err = NewNonceManager(issuer, clock, 1)
	assert.NoError(t, err)
}

func TestGetNonce(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("ca1")

	lib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	lib.On("RandModOrder", rnd).Return(rmo, nil)

	issuer.On("IdemixRand").Return(rnd)

	noncestr := util.B64Encode(idemix.BigToBytes(rmo))
	now := time.Now()
	nonceObj := &Nonce{
		Val:    noncestr,
		Expiry: now.UTC().Add(time.Second * 15),
		Level:  1,
	}

	numResultForRowsAffectedCalls := 0
	f1 := getResultForRowsAffectedFunc(&numResultForRowsAffectedCalls)
	result := new(dmocks.Result)
	result.On("RowsAffected").Return(f1, nil)

	db := new(dmocks.FabricCADB)
	numResultForInsertNonceCalls := 0
	numErrorForInsertNonceCalls := 0
	f2 := getResultForInsertNonceFunc(result, &numResultForInsertNonceCalls)
	f3 := getErrorForInsertNonceFunc(result, &numErrorForInsertNonceCalls)
	db.On("NamedExec", "InsertNonce", InsertNonce, nonceObj).Return(f2, f3)
	issuer.On("DB").Return(db)

	opts := &Config{
		NonceExpiration:    "15s",
		NonceSweepInterval: "15m",
	}
	clock := new(mocks.Clock)
	clock.On("Now").Return(now)
	issuer.On("Config").Return(opts)
	issuer.On("IdemixLib").Return(lib)
	nm, err := NewNonceManager(issuer, clock, 1)

	_, err = nm.GetNonce()
	assert.Error(t, err, "Executing insert SQL should return an error")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to add nonce to the datastore")
	}

	_, err = nm.GetNonce()
	assert.Error(t, err, "Get rows affected from result should return an error")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to add nonce to the datastore; no rows affected")
	}

	_, err = nm.GetNonce()
	assert.Error(t, err, "Get rows affected from result should return an error")
	if err != nil {
		assert.Contains(t, err.Error(), "Expected to affect 1 entry in revocation component info table but affected")
	}

	_, err = nm.GetNonce()
	assert.NoError(t, err)
}

func TestCheckNonce(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("ca1")

	lib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	lib.On("RandModOrder", rnd).Return(rmo)

	issuer.On("IdemixRand").Return(rnd)
	issuer.On("GetIdemixLib").Return(lib)
	noncestr := util.B64Encode(idemix.BigToBytes(rmo))

	db := new(dmocks.FabricCADB)
	tx := new(dmocks.FabricCATx)
	tx.On("Commit", "CheckNonce").Return(nil)
	tx.On("Rollback", "CheckNonce").Return(nil)
	nonces := []Nonce{}
	tx.On("Rebind", SelectNonce).Return(SelectNonce)
	db.On("BeginTx").Return(tx)
	numTxSelectCalls := 0
	f := getTxSelectNonceFunc(&nonces, noncestr, &numTxSelectCalls)
	tx.On("Select", "GetNonce", &nonces, SelectNonce, noncestr).Return(f)
	numTxRemoveResultCalls := 0
	numTxRemoveErrorCalls := 0
	tx.On("Rebind", RemoveNonce).Return(RemoveNonce)
	f1 := getTxRemoveNonceResultFunc(noncestr, &numTxRemoveResultCalls)
	f2 := getTxRemoveNonceErrorFunc(&numTxRemoveErrorCalls)
	tx.On("Exec", "GetNonce", RemoveNonce, noncestr).Return(f1, f2)
	issuer.On("DB").Return(db)

	opts := &Config{
		NonceExpiration:    "15s",
		NonceSweepInterval: "15m",
	}
	issuer.On("Config").Return(opts)
	now := time.Now()
	clock := new(mocks.Clock)
	clock.On("Now").Return(now)
	nm, err := NewNonceManager(issuer, clock, 1)
	if err != nil {
		t.Fatalf("Failed to get new instance of Nonce Manager")
	}
	err = nm.CheckNonce(rmo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to retrieve nonce from the datastore")

	err = nm.CheckNonce(rmo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Nonce not found in the datastore")

	err = nm.CheckNonce(rmo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Nonce is either unknown or has expired")

	err = nm.CheckNonce(rmo)
	assert.NoError(t, err)

	err = nm.CheckNonce(rmo)
	assert.NoError(t, err)
}

func TestSweepExpiredNonces(t *testing.T) {
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("ca1")
	now := time.Now()

	numRemoveExpiredNoncesErrorFuncCalls := 0
	f := getRemoveExpiredNoncesErrorFunc(&numRemoveExpiredNoncesErrorFuncCalls)
	db := new(dmocks.FabricCADB)
	db.On("Rebind", RemoveExpiredNonces).Return(RemoveExpiredNonces)
	db.On("Exec", "RemoveExpiredNonces", RemoveExpiredNonces, now.UTC()).Return(nil, f) // errors.New("error"))
	issuer.On("DB").Return(db)

	lib := new(mocks.Lib)
	opts := &Config{
		NonceExpiration:    "15s",
		NonceSweepInterval: "15m",
	}
	issuer.On("Config").Return(opts)
	issuer.On("IdemixLib").Return(lib)
	clock := new(mocks.Clock)
	clock.On("Now").Return(now)
	nm, err := NewNonceManager(issuer, clock, 1)
	if err != nil {
		t.Fatalf("Failed to get new instance of Nonce Manager")
	}
	err = nm.SweepExpiredNonces()
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to remove expired nonces from DB")
	}

	err = nm.SweepExpiredNonces()
	assert.NoError(t, err)
}

func getResultForInsertNonceFunc(result sql.Result, numResultForInsertNonceCalls *int) func(string, string, interface{}) sql.Result {
	return func(funcName string, query string, args interface{}) sql.Result {
		if *numResultForInsertNonceCalls == 0 {
			*numResultForInsertNonceCalls = *numResultForInsertNonceCalls + 1
			return nil
		}
		return result

	}
}
func getErrorForInsertNonceFunc(result sql.Result, numErrorForInsertNonceCalls *int) func(string, string, interface{}) error {
	return func(funcName string, query string, args interface{}) error {
		if *numErrorForInsertNonceCalls == 0 {
			*numErrorForInsertNonceCalls = *numErrorForInsertNonceCalls + 1
			return errors.New("Error executing insert")
		}
		return nil
	}
}
func getResultForRowsAffectedFunc(numResultForRowsAffectedCalls *int) func() int64 {
	return func() int64 {
		if *numResultForRowsAffectedCalls == 0 {
			*numResultForRowsAffectedCalls = *numResultForRowsAffectedCalls + 1
			return int64(0)
		}
		if *numResultForRowsAffectedCalls == 1 {
			*numResultForRowsAffectedCalls = *numResultForRowsAffectedCalls + 1
			return int64(2)
		}
		return int64(1)
	}
}

func getTxSelectNonceFunc(nonces *[]Nonce, noncestr string, numTxSelectCalls *int) func(string, interface{}, string, ...interface{}) error {
	return func(funcName string, dest interface{}, query string, args ...interface{}) error {
		if *numTxSelectCalls == 0 {
			*numTxSelectCalls = *numTxSelectCalls + 1
			return errors.New("Getting a nonce from DB failed")
		}
		if *numTxSelectCalls == 1 {
			*numTxSelectCalls = *numTxSelectCalls + 1
			return nil
		}

		destNonces, _ := dest.(*[]Nonce)
		if *numTxSelectCalls == 2 {
			*destNonces = append(*destNonces, Nonce{
				Val:    noncestr,
				Expiry: time.Now().Add(-1 * time.Minute),
			})
		}
		*destNonces = append(*destNonces, Nonce{
			Val:    noncestr,
			Expiry: time.Now().Add(time.Minute),
		})
		*numTxSelectCalls = *numTxSelectCalls + 1
		return nil
	}
}

func getTxRemoveNonceResultFunc(noncestr string, numTxRemoveResultCalls *int) func(string, string, ...interface{}) sql.Result {
	return func(funcName, query string, args ...interface{}) sql.Result {
		if *numTxRemoveResultCalls == 0 {
			*numTxRemoveResultCalls = *numTxRemoveResultCalls + 1
			return nil
		}
		result := new(dmocks.Result)
		if *numTxRemoveResultCalls == 1 {
			result.On("RowsAffected").Return(int64(2), nil)
			*numTxRemoveResultCalls = *numTxRemoveResultCalls + 1
			return result
		}
		result.On("RowsAffected").Return(int64(1), nil)
		return result
	}
}

func getTxRemoveNonceErrorFunc(numTxRemoveErrorCalls *int) func(string, string, ...interface{}) error {
	return func(funcName, query string, args ...interface{}) error {
		if *numTxRemoveErrorCalls == 0 {
			*numTxRemoveErrorCalls = *numTxRemoveErrorCalls + 1
			return errors.New("Removing nonce from DB failed")
		}
		return nil
	}
}

func getRemoveExpiredNoncesErrorFunc(numRemoveExpiredNoncesErrorFuncCalls *int) func(string, string, ...interface{}) error {
	return func(string, string, ...interface{}) error {
		if *numRemoveExpiredNoncesErrorFuncCalls == 0 {
			*numRemoveExpiredNoncesErrorFuncCalls = *numRemoveExpiredNoncesErrorFuncCalls + 1
			return errors.New("Failed to remove expired nonces from DB")
		}
		return nil
	}
}
