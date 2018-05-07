/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"fmt"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

const (
	// InsertRCInfo is the SQL for inserting revocation authority info
	InsertRCInfo = "INSERT into revocation_authority_info(epoch, next_handle, lasthandle_in_pool, level) VALUES (:epoch, :next_handle, :lasthandle_in_pool, :level)"
	// SelectRCInfo is the query string for getting revocation authority info
	SelectRCInfo = "SELECT * FROM revocation_authority_info"
	// UpdateNextAndLastHandle is the SQL for updating next and last revocation handle
	UpdateNextAndLastHandle = "UPDATE revocation_authority_info SET next_handle = ? AND lasthandle_in_pool = ? WHERE (epoch = ?)"
	// UpdateNextHandle s the SQL for updating next revocation handle
	UpdateNextHandle = "UPDATE revocation_authority_info SET next_handle = ? WHERE (epoch = ?)"
	// DefaultRevocationHandlePoolSize is the default revocation handle pool size
	DefaultRevocationHandlePoolSize = 100
)

// RevocationHandle is the identifier of the credential using which a user can
// prove to the verifier that his/her credential is not revoked with a zero knowledge
// proof
type RevocationHandle int

// RevocationAuthority is responsible for generating revocation handles and
// credential revocation info (CRI)
type RevocationAuthority interface {
	GetNewRevocationHandle() (*RevocationHandle, error)
}

// RevocationComponentInfo is the revocation authority information record that is
// stored in the database
type RevocationComponentInfo struct {
	Epoch                int `db:"epoch"`
	NextRevocationHandle int `db:"next_handle"`
	LastHandleInPool     int `db:"lasthandle_in_pool"`
	Level                int `db:"level"`
}

// revocationAuthority implements RevocationComponent interface
type revocationAuthority struct {
	issuer MyIssuer
	db     dbutil.FabricCADB
	info   *RevocationComponentInfo
}

// NewRevocationAuthority constructor for revocation authority
func NewRevocationAuthority(issuer MyIssuer, level int) (RevocationAuthority, error) {
	rc := &revocationAuthority{
		issuer, issuer.DB(), nil,
	}
	var err error
	rc.info, err = rc.getRCInfoFromDB()
	if err == nil {
		// If epoch is 0, it means this is the first time revocation authority is being
		// initialized. Initilize revocation authority info and store it in the database
		if rc.info.Epoch == 0 {
			rcInfo := RevocationComponentInfo{
				Epoch:                1,
				NextRevocationHandle: 1,
				LastHandleInPool:     issuer.Config().RHPoolSize,
				Level:                level,
			}
			err = rc.addRCInfoToDB(&rcInfo)
		}
	}
	if err != nil {
		return nil, errors.WithMessage(err,
			fmt.Sprintf("Failed to initialize revocation authority for Issuer '%s'", issuer.Name()))
	}
	return rc, nil
}

// GetNewRevocationHandle returns a new revocation handle
func (rc *revocationAuthority) GetNewRevocationHandle() (*RevocationHandle, error) {
	h, err := rc.getNextRevocationHandle()
	if err != nil {
		return nil, err
	}
	rh := RevocationHandle(h)
	return &rh, err
}

func (rc *revocationAuthority) getRCInfoFromDB() (*RevocationComponentInfo, error) {
	rcinfos := []RevocationComponentInfo{}
	err := rc.db.Select(&rcinfos, SelectRCInfo)
	if err != nil {
		return nil, err
	}
	if len(rcinfos) == 0 {
		return &RevocationComponentInfo{
			0, 0, 0, 0,
		}, nil
	}
	return &rcinfos[0], nil
}

func (rc *revocationAuthority) addRCInfoToDB(rcInfo *RevocationComponentInfo) error {
	res, err := rc.db.NamedExec(InsertRCInfo, rcInfo)
	if err != nil {
		return errors.New("Failed to insert revocation authority info into database")
	}

	numRowsAffected, err := res.RowsAffected()
	if numRowsAffected == 0 {
		return errors.New("Failed to insert the revocation authority info record; no rows affected")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to affect 1 entry in revocation authority info table but affected %d",
			numRowsAffected)
	}
	return err
}

// getNextRevocationHandle returns next revocation handle
func (rc *revocationAuthority) getNextRevocationHandle() (int, error) {
	result, err := doTransaction(rc.db, rc.getNextRevocationHandleTx, nil)
	if err != nil {
		return 0, err
	}

	nextHandle := result.(int)
	return nextHandle, nil
}

func (rc *revocationAuthority) getNextRevocationHandleTx(tx dbutil.FabricCATx, args ...interface{}) (interface{}, error) {
	var err error

	// Get the latest revocation authority info from the database
	rcInfos := []RevocationComponentInfo{}
	query := SelectRCInfo
	err = tx.Select(&rcInfos, tx.Rebind(query))
	if err != nil {
		return nil, errors.New("Failed to get revocation authority info from database")
	}
	if len(rcInfos) == 0 {
		return nil, errors.New("No revocation authority info found in database")
	}
	rcInfo := rcInfos[0]

	nextHandle := rcInfo.NextRevocationHandle
	newNextHandle := rcInfo.NextRevocationHandle + 1
	var inQuery string
	if nextHandle == rcInfo.LastHandleInPool {
		newLastHandleInPool := rcInfo.LastHandleInPool + 100
		query = UpdateNextAndLastHandle
		inQuery, args, err = sqlx.In(query, newNextHandle, newLastHandleInPool, rcInfo.Epoch)
	} else {
		query = UpdateNextHandle
		inQuery, args, err = sqlx.In(query, newNextHandle, rcInfo.Epoch)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to construct query '%s'", query)
	}
	_, err = tx.Exec(tx.Rebind(inQuery), args...)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to update revocation authority info")
	}

	return nextHandle, nil
}

func doTransaction(db dbutil.FabricCADB, doit func(tx dbutil.FabricCATx, args ...interface{}) (interface{}, error), args ...interface{}) (interface{}, error) {
	if db == nil {
		return nil, errors.New("Failed to correctly setup database connection")
	}
	tx := db.BeginTx()
	result, err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			errMsg := fmt.Sprintf("Error encountered while rolling back transaction: %s, original error: %s", err2.Error(), err.Error())
			log.Errorf(errMsg)
			return nil, errors.New(errMsg)
		}
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "Error encountered while committing transaction")
	}

	return result, nil
}
