/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/cloudflare/cfssl/log"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

const (
	// InsertRAInfo is the SQL for inserting revocation authority info
	InsertRAInfo = "INSERT into revocation_authority_info(epoch, private_key, public_key, next_handle, lasthandle_in_pool, level) VALUES (:epoch, :private_key, :public_key, :next_handle, :lasthandle_in_pool, :level)"
	// SelectRAInfo is the query string for getting revocation authority info
	SelectRAInfo = "SELECT * FROM revocation_authority_info"
	// UpdateNextAndLastHandle is the SQL for updating next and last revocation handle
	UpdateNextAndLastHandle = "UPDATE revocation_authority_info SET next_handle = ? AND lasthandle_in_pool = ? WHERE (epoch = ?)"
	// UpdateNextHandle s the SQL for updating next revocation handle
	UpdateNextHandle = "UPDATE revocation_authority_info SET next_handle = ? WHERE (epoch = ?)"
	// DefaultRevocationHandlePoolSize is the default revocation handle pool size
	DefaultRevocationHandlePoolSize = 100
)

// RevocationAuthority is responsible for generating revocation handles and
// credential revocation info (CRI)
type RevocationAuthority interface {
	GetNewRevocationHandle() (*fp256bn.BIG, error)
	CreateCRI() (*idemix.CredentialRevocationInformation, error)
}

// RevocationAuthorityInfo is the revocation authority information record that is
// stored in the database
type RevocationAuthorityInfo struct {
	Epoch                int    `db:"epoch"`
	PrivateKey           string `db:"private_key"`
	PublicKey            string `db:"public_key"`
	NextRevocationHandle int    `db:"next_handle"`
	LastHandleInPool     int    `db:"lasthandle_in_pool"`
	Level                int    `db:"level"`
}

// revocationAuthority implements RevocationComponent interface
type revocationAuthority struct {
	issuer     MyIssuer
	key        *ecdsa.PrivateKey
	db         dbutil.FabricCADB
	currentCRI *idemix.CredentialRevocationInformation
}

// NewRevocationAuthority constructor for revocation authority
func NewRevocationAuthority(issuer MyIssuer, level int) (RevocationAuthority, error) {
	ra := &revocationAuthority{
		issuer: issuer,
		db:     issuer.DB(),
	}
	var err error
	info, err := ra.getRAInfoFromDB()
	if err == nil {
		// If epoch is 0, it means this is the first time revocation authority is being
		// initialized. Initilize revocation authority info and store it in the database
		if info.Epoch == 0 {
			ra.key, err = ra.issuer.IdemixLib().GenerateLongTermRevocationKey()
			if err != nil {
				return nil, errors.WithMessage(err,
					fmt.Sprintf("Failed to generate long term key for the revocation authority '%s'", ra.issuer.Name()))
			}
			pk, pubkey, err1 := EncodeKeys(ra.key, &ra.key.PublicKey)
			if err1 != nil {
				return nil, errors.Wrapf(err1, "Failed to encode long term key of the revocation authority '%s'", ra.issuer.Name())
			}
			rcInfo := RevocationAuthorityInfo{
				Epoch:                1,
				PrivateKey:           pk,
				PublicKey:            pubkey,
				NextRevocationHandle: 1,
				LastHandleInPool:     issuer.Config().RHPoolSize,
				Level:                level,
			}
			err = ra.addRAInfoToDB(&rcInfo)
			if err == nil {
				info = &rcInfo
			}
		} else {
			pk, pubk, err := DecodeKeys(info.PrivateKey, info.PublicKey)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to decode revocation authority keys")
			}
			pk.PublicKey = *pubk
			ra.key = pk
		}
	}
	if err != nil {
		return nil, errors.WithMessage(err,
			fmt.Sprintf("Failed to initialize revocation authority for Issuer '%s'", issuer.Name()))
	}
	return ra, nil
}

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
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get revoked credentials while generating CRI for the issuer: %s", ra.issuer.Name()))
	}

	unrevokedHandles := ra.getUnRevokedHandles(info, revokedCreds)

	alg := idemix.ALG_NO_REVOCATION
	if len(revokedCreds) > 0 {
		alg = idemix.ALG_PLAIN_SIGNATURE
	}
	cri, err := ra.issuer.IdemixLib().CreateCRI(ra.key, unrevokedHandles, info.Epoch, alg, ra.issuer.IdemixRand())
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

func (ra *revocationAuthority) getUnRevokedHandles(info *RevocationAuthorityInfo, revokedCreds []CredRecord) []*fp256bn.BIG {
	log.Debugf("RA '%s' Getting revoked revocation handles for epoch %d", ra.issuer.Name(), info.Epoch)
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
	err := ra.db.Select(&rcinfos, SelectRAInfo)
	if err != nil {
		return nil, err
	}
	if len(rcinfos) == 0 {
		return &RevocationAuthorityInfo{
			0, "", "", 0, 0, 0,
		}, nil
	}
	return &rcinfos[0], nil
}

func (ra *revocationAuthority) addRAInfoToDB(rcInfo *RevocationAuthorityInfo) error {
	res, err := ra.db.NamedExec(InsertRAInfo, rcInfo)
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
	result, err := doTransaction(ra.db, ra.getNextRevocationHandleTx, nil)
	if err != nil {
		return 0, err
	}

	nextHandle := result.(int)
	return nextHandle, nil
}

func (ra *revocationAuthority) getNextRevocationHandleTx(tx dbutil.FabricCATx, args ...interface{}) (interface{}, error) {
	var err error

	// Get the latest revocation authority info from the database
	rcInfos := []RevocationAuthorityInfo{}
	query := SelectRAInfo
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
		newLastHandleInPool := rcInfo.LastHandleInPool + ra.issuer.Config().RHPoolSize
		newEpoch := rcInfo.Epoch + 1
		query = UpdateNextAndLastHandle
		inQuery, args, err = sqlx.In(query, newNextHandle, newLastHandleInPool, newEpoch)
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

// EncodeKeys encodes ECDSA key pair to PEM encoding
func EncodeKeys(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string, error) {
	encodedPK, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", errors.Wrap(err, "Failed to encode ECDSA private key")
	}
	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})

	encodedPubKey, err := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPubKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedPubKey})
	if err != nil {
		return "", "", errors.Wrap(err, "Failed to encode ECDSA public key")
	}
	return string(pemEncodedPK), string(pemEncodedPubKey), nil
}

// DecodeKeys decodes ECDSA key pair that are pem encoded
func DecodeKeys(pemEncodedPK string, pemEncodedPubKey string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemEncodedPK))
	if block == nil {
		return nil, nil, errors.New("Failed to decode ECDSA private key")
	}
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse ECDSA private key bytes")
	}
	blockPub, _ := pem.Decode([]byte(pemEncodedPubKey))
	if blockPub == nil {
		return nil, nil, errors.New("Failed to decode ECDSA public key")
	}
	key, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse ECDSA public key bytes")
	}
	publicKey := key.(*ecdsa.PublicKey)

	return pk, publicKey, nil
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
