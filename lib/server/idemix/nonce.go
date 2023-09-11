/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

const (
	// InsertNonce is the SQL for inserting a nonce
	InsertNonce = "INSERT into nonces(val, expiry, level) VALUES (:val, :expiry, :level)"
	// SelectNonce is query string for getting a particular nonce
	SelectNonce = "SELECT * FROM nonces WHERE (val = ?)"
	// RemoveNonce is the query string for removing a specified nonce
	RemoveNonce = "DELETE FROM nonces WHERE (val = ?)"
	// RemoveExpiredNonces is the SQL string removing expired nonces
	RemoveExpiredNonces = "DELETE FROM nonces WHERE (expiry < ?)"
	// DefaultNonceExpiration is the default value for nonce expiration
	DefaultNonceExpiration = "15s"
	// DefaultNonceSweepInterval is the default value for nonce sweep interval
	DefaultNonceSweepInterval = "15m"
)

// Nonce represents a nonce
type Nonce struct {
	Val    string    `db:"val"`
	Expiry time.Time `db:"expiry"`
	Level  int       `db:"level"`
}

//go:generate mockery --name NonceManager --case underscore

// NonceManager represents nonce manager that is responsible for
// getting a new nonce
type NonceManager interface {
	// GetNonce creates a nonce, stores it in the database and returns it
	GetNonce() ([]byte, error)
	// CheckNonce checks if the specified nonce exists in the database and has not expired
	CheckNonce(nonce []byte) error
	// SweepExpiredNonces removes expired nonces from the database
	SweepExpiredNonces() error
}

//go:generate mockery --name ReadNonce --case underscore
type ReadNonce interface {
	Read() ([]byte, error)
}

// Clock provides time related functions
//
//go:generate mockery --name Clock --case underscore
type Clock interface {
	Now() time.Time
}

// NonceManagerImpl implements NonceManager interface
type NonceManagerImpl struct {
	nonceExpiration    time.Duration
	nonceSweepInterval time.Duration
	clock              Clock
	issuer             *IssuerInst
	level              int
	ReadNonce          ReadNonce
}

type readNonceImpl struct {
}

func (*readNonceImpl) Read() ([]byte, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		fmt.Println(">>>>>>>>>>>>>>>>>>>")
		return nil, err
	}

	return nonceBytes, err
}

// NewNonceManager returns an instance of an object that implements NonceManager interface
func NewNonceManager(issuer *IssuerInst, clock Clock, level int) (NonceManager, error) {
	var err error
	mgr := &NonceManagerImpl{
		issuer: issuer,
		clock:  clock,
		level:  level,
	}
	opts := issuer.Cfg
	mgr.nonceExpiration, err = time.ParseDuration(opts.NonceExpiration)
	if err != nil {
		return nil, errors.Wrapf(err, fmt.Sprintf("Failed to parse idemix.nonceexpiration config option while initializing Nonce manager for Issuer '%s'",
			issuer.Name))
	}
	mgr.nonceSweepInterval, err = time.ParseDuration(opts.NonceSweepInterval)
	if err != nil {
		return nil, errors.Wrapf(err, fmt.Sprintf("Failed to parse idemix.noncesweepinterval config option while initializing Nonce manager for Issuer '%s'",
			issuer.Name))
	}
	mgr.ReadNonce = &readNonceImpl{}
	return mgr, nil
}

// GetNonce returns a new nonce
func (nm *NonceManagerImpl) GetNonce() ([]byte, error) {
	nonceBytes, err := nm.ReadNonce.Read()
	if err != nil {
		return nil, err
	}

	err = nm.insertNonceInDB(&Nonce{
		Val:    util.B64Encode(nonceBytes),
		Expiry: nm.clock.Now().UTC().Add(nm.nonceExpiration),
		Level:  nm.level,
	})
	if err != nil {
		log.Errorf("Failed to store nonce: %s", err.Error())
		return nil, errors.WithMessage(err, "Failed to store nonce")
	}
	return nonceBytes, nil
}

// CheckNonce checks if the specified nonce is valid (is in DB and has not expired)
// and the nonce is removed from DB
func (nm *NonceManagerImpl) CheckNonce(nonceBytes []byte) error {
	queryParam := util.B64Encode(nonceBytes)
	nonceRec, err := doTransaction("CheckNonce", nm.issuer.Db, nm.getNonceFromDB, queryParam)
	if err != nil {
		return err
	}
	nonceFromDB := nonceRec.(Nonce)
	log.Debugf("Retrieved nonce from DB: %+v, %s", nonceRec, queryParam)

	if nonceFromDB.Val != queryParam || nonceFromDB.Expiry.Before(time.Now().UTC()) {
		return errors.New("Nonce is either unknown or has expired")
	}
	return nil
}

// SweepExpiredNonces sweeps expired nonces
func (nm *NonceManagerImpl) SweepExpiredNonces() error {
	return nm.sweep(nm.clock.Now().UTC())
}

// StartNonceSweeper starts a separate thread that will remove expired
// nonces at the interval specified by the idemix.noncesweepinterval. This
// function should be called while initializing the server.
func (nm *NonceManagerImpl) StartNonceSweeper() {
	go func() {
		ticker := time.NewTicker(nm.nonceSweepInterval)
		for t := range ticker.C {
			nm.sweep(t.UTC())
		}
	}()
}

// sweep deletes all nonces that have expired (whose expiry is less than current timestamp)
func (nm *NonceManagerImpl) sweep(curTime time.Time) error {
	log.Debugf("Cleaning up expired nonces for CA '%s'", nm.issuer.Name)
	return nm.removeExpiredNoncesFromDB(curTime)
}

// Gets the specified nonce from DB and removes it from the DB
func (nm *NonceManagerImpl) getNonceFromDB(tx db.FabricCATx, args ...interface{}) (interface{}, error) {
	nonces := []Nonce{}
	err := tx.Select("GetNonce", &nonces, tx.Rebind(SelectNonce), args...)
	if err != nil {
		log.Errorf("Failed to get nonce from DB: %s", err.Error())
		return nil, errors.New("Failed to retrieve nonce from the datastore")
	}
	if len(nonces) == 0 {
		return nil, errors.New("Nonce not found in the datastore")
	}
	result, err := tx.Exec("GetNonce", tx.Rebind(RemoveNonce), args...)
	if err != nil {
		log.Errorf("Failed to remove nonce %s from DB: %s", args[0], err.Error())
		return nonces[0], nil
	}
	numRowsAffected, err := result.RowsAffected()
	if numRowsAffected != 1 {
		log.Errorf("Tried to remove one nonce from DB but %d were removed", numRowsAffected)
	}
	return nonces[0], nil
}

func (nm *NonceManagerImpl) removeExpiredNoncesFromDB(curTime time.Time) error {
	_, err := nm.issuer.Db.Exec("RemoveExpiredNonces", nm.issuer.Db.Rebind(RemoveExpiredNonces), curTime)
	if err != nil {
		log.Errorf("Failed to remove expired nonces from DB for CA '%s': %s", nm.issuer.Name, err.Error())
		return errors.New("Failed to remove expired nonces from DB")
	}
	return nil
}

func (nm *NonceManagerImpl) insertNonceInDB(nonce *Nonce) error {
	res, err := nm.issuer.Db.NamedExec("InsertNonce", InsertNonce, nonce)
	if err != nil {
		log.Errorf("Failed to add nonce to DB: %s", err.Error())
		return errors.New("Failed to add nonce to the datastore")
	}

	numRowsAffected, err := res.RowsAffected()
	if numRowsAffected == 0 {
		return errors.New("Failed to add nonce to the datastore; no rows affected")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to affect 1 entry in revocation component info table but affected %d",
			numRowsAffected)
	}
	return err
}
