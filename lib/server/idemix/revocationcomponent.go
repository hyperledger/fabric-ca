/*
Copyright IBM Corp. 2018 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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
	// InsertRCInfo is the SQL for inserting revocation component info
	InsertRCInfo = "INSERT into revocation_component_info(epoch, next_handle, lasthandle_in_pool, level) VALUES (:epoch, :next_handle, :lasthandle_in_pool, :level)"
	// SelectRCInfo is the query string for getting revocation component info
	SelectRCInfo = "SELECT * FROM revocation_component_info"
	// UpdateNextAndLastHandle is the SQL for updating next and last revocation handle
	UpdateNextAndLastHandle = "UPDATE revocation_component_info SET next_handle = ? AND lasthandle_in_pool = ? WHERE (epoch = ?)"
	// UpdateNextHandle s the SQL for updating next revocation handle
	UpdateNextHandle = "UPDATE revocation_component_info SET next_handle = ? WHERE (epoch = ?)"
	// DefaultRevocationHandlePoolSize is the default revocation handle pool size
	DefaultRevocationHandlePoolSize = 100
)

// RevocationHandle is the identifier of the credential using which a user can
// prove to the verifier that his/her credential is not revoked with a zero knowledge
// proof
type RevocationHandle int

// RevocationComponent is responsible for generating revocation handles and
// credential revocation info (CRI)
type RevocationComponent interface {
	GetNewRevocationHandle() (*RevocationHandle, error)
}

// RevocationComponentInfo is the revocation component information record that is
// stored in the database
type RevocationComponentInfo struct {
	Epoch                int `db:"epoch"`
	NextRevocationHandle int `db:"next_handle"`
	LastHandleInPool     int `db:"lasthandle_in_pool"`
	Level                int `db:"level"`
}

// revocationComponent implements RevocationComponent interface
type revocationComponent struct {
	ca   CA
	db   dbutil.FabricCADB
	info *RevocationComponentInfo
	opts *CfgOptions
}

// CfgOptions encapsulates Idemix related the configuration options
type CfgOptions struct {
	RevocationHandlePoolSize int    `def:"100" help:"Specifies revocation handle pool size"`
	NonceExpiration          string `def:"15s" help:"Duration after which a nonce expires"`
	NonceSweepInterval       string `def:"15m" help:"Interval at which expired nonces are deleted"`
}

// NewRevocationComponent constructor for revocation component
func NewRevocationComponent(ca CA, opts *CfgOptions, level int) (RevocationComponent, error) {
	rc := &revocationComponent{
		ca, ca.DB(), nil, opts,
	}
	var err error
	rc.info, err = rc.getRCInfoFromDB()
	if err == nil {
		// If epoch is 0, it means this is the first time revocation component is being
		// initialized. Initilize revocation component info and store it in the database
		if rc.info.Epoch == 0 {
			rcInfo := RevocationComponentInfo{
				Epoch:                1,
				NextRevocationHandle: 1,
				LastHandleInPool:     opts.RevocationHandlePoolSize,
				Level:                level,
			}
			err = rc.addRCInfoToDB(&rcInfo)
		}
	}
	if err != nil {
		return nil, errors.WithMessage(err,
			fmt.Sprintf("Failed to initialize revocation component for CA %s", ca.GetName()))
	}
	return rc, nil
}

// GetNewRevocationHandle returns a new revocation handle
func (rc *revocationComponent) GetNewRevocationHandle() (*RevocationHandle, error) {
	h, err := rc.getNextRevocationHandle()
	if err != nil {
		return nil, err
	}
	rh := RevocationHandle(h)
	return &rh, err
}

func (rc *revocationComponent) getRCInfoFromDB() (*RevocationComponentInfo, error) {
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

func (rc *revocationComponent) addRCInfoToDB(rcInfo *RevocationComponentInfo) error {
	res, err := rc.db.NamedExec(InsertRCInfo, rcInfo)
	if err != nil {
		return errors.New("Failed to insert revocation component info into database")
	}

	numRowsAffected, err := res.RowsAffected()
	if numRowsAffected == 0 {
		return errors.New("Failed to insert the revocation component info record; no rows affected")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to affect 1 entry in revocation component info table but affected %d",
			numRowsAffected)
	}
	return err
}

// getNextRevocationHandle returns next revocation handle
func (rc *revocationComponent) getNextRevocationHandle() (int, error) {
	result, err := doTransaction(rc.db, rc.getNextRevocationHandleTx, nil)
	if err != nil {
		return 0, err
	}

	nextHandle := result.(int)
	return nextHandle, nil
}

func (rc *revocationComponent) getNextRevocationHandleTx(tx dbutil.FabricCATx, args ...interface{}) (interface{}, error) {
	var err error

	// Get the latest revocation component info from the database
	rcInfos := []RevocationComponentInfo{}
	query := SelectRCInfo
	err = tx.Select(&rcInfos, tx.Rebind(query))
	if err != nil {
		return nil, errors.New("Failed to get revocation component info from database")
	}
	if len(rcInfos) == 0 {
		return nil, errors.New("No revocation component info found in database")
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
		return nil, errors.Wrapf(err, "Failed to update revocation component info")
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
