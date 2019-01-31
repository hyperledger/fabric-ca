/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"

	"github.com/cloudflare/cfssl/log"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

const (
	// InsertRAInfo is the SQL for inserting revocation authority info
	InsertRAInfo = "INSERT into revocation_authority_info(epoch, next_handle, lasthandle_in_pool, level) VALUES (:epoch, :next_handle, :lasthandle_in_pool, :level)"
	// SelectRAInfo is the query string for getting revocation authority info
	SelectRAInfo = "SELECT * FROM revocation_authority_info"
	// UpdateNextAndLastHandle is the SQL for updating next and last revocation handle
	UpdateNextAndLastHandle = "UPDATE revocation_authority_info SET next_handle = ?, lasthandle_in_pool = ?, epoch = ? WHERE (epoch = ?)"
	// UpdateNextHandle s the SQL for updating next revocation handle
	UpdateNextHandle = "UPDATE revocation_authority_info SET next_handle = ? WHERE (epoch = ?)"
	// DefaultRevocationHandlePoolSize is the default revocation handle pool size
	DefaultRevocationHandlePoolSize = 1000
)

// RevocationAuthority is responsible for generating revocation handles and
// credential revocation info (CRI)
type RevocationAuthority interface {
	// GetNewRevocationHandle returns new revocation handle, which is required to
	// create a new Idemix credential
	GetNewRevocationHandle() (*fp256bn.BIG, error)
	// CreateCRI returns latest credential revocation information (CRI). CRI contains
	// information that allows a prover to create a proof that the revocation handle associated
	// with his credential is not revoked and by the verifier to verify the non-revocation
	// proof of the prover. Verification will fail if the version of the CRI that verifier has
	// does not match the version of the CRI that prover used to create non-revocation proof.
	// The version of the CRI is specified by the Epoch value associated with the CRI.
	CreateCRI() (*idemix.CredentialRevocationInformation, error)
	// Epoch returns epoch value of the latest CRI
	Epoch() (int, error)
	// PublicKey returns revocation authority's public key
	PublicKey() *ecdsa.PublicKey
}

// RevocationAuthorityInfo is the revocation authority information record that is
// stored in the database
type RevocationAuthorityInfo struct {
	Epoch                int `db:"epoch"`
	NextRevocationHandle int `db:"next_handle"`
	LastHandleInPool     int `db:"lasthandle_in_pool"`
	Level                int `db:"level"`
}

// revocationAuthority implements RevocationComponent interface
type revocationAuthority struct {
	issuer     MyIssuer
	key        RevocationKey
	db         db.FabricCADB
	currentCRI *idemix.CredentialRevocationInformation
}

// NewRevocationAuthority constructor for revocation authority
func NewRevocationAuthority(issuer MyIssuer, level int) (RevocationAuthority, error) {
	ra := &revocationAuthority{
		issuer: issuer,
		db:     issuer.DB(),
	}
	var err error

	err = ra.initKeyMaterial(false)
	if err != nil {
		return nil, err
	}

	info, err := ra.getRAInfoFromDB()
	if err != nil {
		return nil, errors.WithMessage(err,
			fmt.Sprintf("Failed to initialize revocation authority for issuer '%s'", issuer.Name()))
	}

	// If epoch is 0, it means this is the first time revocation authority is being
	// initialized. Initilize revocation authority info and store it in the database
	if info.Epoch == 0 {
		rcInfo := RevocationAuthorityInfo{
			Epoch:                1,
			NextRevocationHandle: 1,
			LastHandleInPool:     issuer.Config().RHPoolSize,
			Level:                level,
		}
		err = ra.addRAInfoToDB(&rcInfo)
		if err != nil {
			return nil, errors.WithMessage(err,
				fmt.Sprintf("Failed to initialize revocation authority for issuer '%s'", issuer.Name()))
		}
		info = &rcInfo
	}

	return ra, nil
}

func (ra *revocationAuthority) initKeyMaterial(renew bool) error {
	log.Debug("Initialize Idemix issuer revocation key material")
	revocationPubKey := ra.issuer.Config().RevocationPublicKeyfile
	revocationPrivKey := ra.issuer.Config().RevocationPrivateKeyfile
	rk := NewRevocationKey(revocationPubKey, revocationPrivKey, ra.issuer.IdemixLib())

	if !renew {
		pubKeyFileExists := util.FileExists(revocationPubKey)
		privKeyFileExists := util.FileExists(revocationPrivKey)
		// If they both exist, the CA was already initialized, load the keys from the disk
		if pubKeyFileExists && privKeyFileExists {
			log.Info("The Idemix issuer revocation public and secret key files already exist")
			log.Infof("   private key file location: %s", revocationPrivKey)
			log.Infof("   public key file location: %s", revocationPubKey)
			err := rk.Load()
			if err != nil {
				return errors.WithMessage(err, fmt.Sprintf("Failed to load revocation key for issuer '%s'", ra.issuer.Name()))
			}
			ra.key = rk
			return nil
		}
	}
	err := rk.SetNewKey()
	if err != nil {
		return errors.WithMessage(err,
			fmt.Sprintf("Failed to generate revocation key for issuer '%s'", ra.issuer.Name()))
	}
	log.Infof("Idemix issuer revocation public and secret keys were generated for CA '%s'", ra.issuer.Name())
	err = rk.Store()
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to store revocation key of issuer '%s'", ra.issuer.Name()))
	}
	ra.key = rk
	return nil
}

// CreateCRI returns latest credential revocation information (CRI). CRI contains
// information that allows a prover to create a proof that the revocation handle associated
// with his credential is not revoked and by the verifier to verify the non-revocation
// proof of the prover. Verification will fail if the version of the CRI that verifier has
// does not match the version of the CRI that prover used to create non-revocation proof.
// The version of the CRI is specified by the Epoch value associated with the CRI.
func (ra *revocationAuthority) CreateCRI() (*idemix.CredentialRevocationInformation, error) {
	info, err := ra.getRAInfoFromDB()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get revocation authority info from datastore")
	}
	if ra.currentCRI != nil && ra.currentCRI.Epoch == int64(info.Epoch) {
		return ra.currentCRI, nil
	}

	revokedCreds, err := ra.issuer.CredDBAccessor().GetRevokedCredentials()
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get revoked credentials while generating CRI for issuer: '%s'", ra.issuer.Name()))
	}

	unrevokedHandles := ra.getUnRevokedHandles(info, revokedCreds)

	alg := idemix.ALG_NO_REVOCATION
	cri, err := ra.issuer.IdemixLib().CreateCRI(ra.key.GetKey(), unrevokedHandles, info.Epoch, alg, ra.issuer.IdemixRand())
	if err != nil {
		return nil, err
	}
	ra.currentCRI = cri
	return ra.currentCRI, nil
}

// GetNewRevocationHandle returns a new revocation handle
func (ra *revocationAuthority) GetNewRevocationHandle() (*fp256bn.BIG, error) {
	h, err := ra.getNextRevocationHandle()
	if err != nil {
		return nil, err
	}
	rh := fp256bn.NewBIGint(h)
	return rh, err
}

// Epoch returns epoch value of the latest CRI
func (ra *revocationAuthority) Epoch() (int, error) {
	info, err := ra.getRAInfoFromDB()
	if err != nil {
		return 0, errors.WithMessage(err, "Revocation authority failed to get latest epoch")
	}
	return info.Epoch, nil
}

// PublicKey returns revocation authority's public key
func (ra *revocationAuthority) PublicKey() *ecdsa.PublicKey {
	return &ra.key.GetKey().PublicKey
}

func (ra *revocationAuthority) getUnRevokedHandles(info *RevocationAuthorityInfo, revokedCreds []CredRecord) []*fp256bn.BIG {
	log.Debugf("RA '%s' is getting revoked revocation handles for epoch %d", ra.issuer.Name(), info.Epoch)
	isRevokedHandle := func(rh *fp256bn.BIG) bool {
		for i := 0; i <= len(revokedCreds)-1; i++ {
			rrhBytes, err := util.B64Decode(revokedCreds[i].RevocationHandle)
			if err != nil {
				log.Debugf("Failed to Base64 decode revocation handle '%s': %s", revokedCreds[i].RevocationHandle, err.Error())
				return false
			}
			rhBytes := idemix.BigToBytes(rh)
			if bytes.Compare(rhBytes, rrhBytes) == 0 {
				return true
			}
		}
		return false
	}
	validHandles := []*fp256bn.BIG{}
	for i := 1; i <= info.LastHandleInPool; i = i + 1 {
		validHandles = append(validHandles, fp256bn.NewBIGint(i))
	}
	for i := len(validHandles) - 1; i >= 0; i-- {
		isrevoked := isRevokedHandle(validHandles[i])
		if isrevoked {
			validHandles = append(validHandles[:i], validHandles[i+1:]...)
		}
	}
	return validHandles
}

func (ra *revocationAuthority) getRAInfoFromDB() (*RevocationAuthorityInfo, error) {
	rcinfos := []RevocationAuthorityInfo{}
	err := ra.db.Select("GetRAInfo", &rcinfos, SelectRAInfo)
	if err != nil {
		return nil, err
	}
	if len(rcinfos) == 0 {
		return &RevocationAuthorityInfo{
			0, 0, 0, 0,
		}, nil
	}
	return &rcinfos[0], nil
}

func (ra *revocationAuthority) addRAInfoToDB(rcInfo *RevocationAuthorityInfo) error {
	res, err := ra.db.NamedExec("AddRAInfo", InsertRAInfo, rcInfo)
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
func (ra *revocationAuthority) getNextRevocationHandle() (int, error) {
	result, err := doTransaction("GetNextRevocationHandle", ra.db, ra.getNextRevocationHandleTx, nil)
	if err != nil {
		return 0, err
	}

	nextHandle := result.(int)
	return nextHandle, nil
}

func (ra *revocationAuthority) getNextRevocationHandleTx(tx db.FabricCATx, args ...interface{}) (interface{}, error) {
	var err error

	// Get the latest revocation authority info from the database
	rcInfos := []RevocationAuthorityInfo{}
	query := SelectRAInfo
	err = tx.Select("GetRAInfo", &rcInfos, tx.Rebind(query))
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
		newLastHandleInPool := rcInfo.LastHandleInPool + ra.issuer.Config().RHPoolSize
		newEpoch := rcInfo.Epoch + 1
		query = UpdateNextAndLastHandle
		inQuery, args, err = sqlx.In(query, newNextHandle, newLastHandleInPool, newEpoch, rcInfo.Epoch)
	} else {
		query = UpdateNextHandle
		inQuery, args, err = sqlx.In(query, newNextHandle, rcInfo.Epoch)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to construct query '%s'", query)
	}
	_, err = tx.Exec("GetNextRevocationHandle", tx.Rebind(inQuery), args...)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to update revocation authority info")
	}

	return nextHandle, nil
}

func doTransaction(funcName string, db db.FabricCADB, doit func(tx db.FabricCATx, args ...interface{}) (interface{}, error), args ...interface{}) (interface{}, error) {
	if db == nil {
		return nil, errors.New("Failed to correctly setup database connection")
	}
	tx := db.BeginTx()
	result, err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback(funcName)
		if err2 != nil {
			errMsg := fmt.Sprintf("Error encountered while rolling back transaction: %s, original error: %s", err2.Error(), err.Error())
			log.Errorf(errMsg)
			return nil, errors.New(errMsg)
		}
		return nil, err
	}

	err = tx.Commit(funcName)
	if err != nil {
		return nil, errors.Wrap(err, "Error encountered while committing transaction")
	}

	return result, nil
}
