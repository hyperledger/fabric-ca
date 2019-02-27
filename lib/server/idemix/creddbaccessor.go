/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"fmt"
	"reflect"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/kisielk/sqlstruct"
	"github.com/pkg/errors"
)

const (
	// InsertCredentialSQL is the SQL to add a credential to database
	InsertCredentialSQL = `
INSERT INTO credentials (id, revocation_handle, cred, ca_label, status, reason, expiry, revoked_at, level)
	VALUES (:id, :revocation_handle, :cred, :ca_label, :status, :reason, :expiry, :revoked_at, :level);`

	// SelectCredentialByIDSQL is the SQL for getting credentials of a user
	SelectCredentialByIDSQL = `
SELECT %s FROM credentials
WHERE (id = ?);`

	// SelectCredentialSQL is the SQL for getting a credential given a revocation handle
	SelectCredentialSQL = `
SELECT %s FROM credentials
WHERE (revocation_handle = ?);`

	// SelectRevokedCredentialSQL is the SQL for getting revoked credentials
	SelectRevokedCredentialSQL = `
SELECT %s FROM credentials
WHERE (status = 'revoked');`

	// UpdateRevokeCredentialSQL is the SQL for updating status of a credential to revoked
	UpdateRevokeCredentialSQL = `
UPDATE credentials
SET status='revoked', revoked_at=CURRENT_TIMESTAMP, reason=:reason
WHERE (id = :id AND status != 'revoked');`

	// DeleteCredentialbyID is the SQL for deleting credential of a user
	DeleteCredentialbyID = `
DELETE FROM credentials
		WHERE (id = ?);`
)

// CredRecord represents a credential database record
type CredRecord struct {
	ID               string    `db:"id"`
	RevocationHandle string    `db:"revocation_handle"`
	Cred             string    `db:"cred"`
	CALabel          string    `db:"ca_label"`
	Status           string    `db:"status"`
	Reason           int       `db:"reason"`
	Expiry           time.Time `db:"expiry"`
	RevokedAt        time.Time `db:"revoked_at"`
	Level            int       `db:"level"`
}

//go:generate mockery -name CredDBAccessor -case underscore

// CredDBAccessor is the accessor for credentials database table
type CredDBAccessor interface {
	// Sets reference to datastore object
	SetDB(db db.FabricCADB)
	// InsertCredential inserts specified Idemix credential record into database
	InsertCredential(cr CredRecord) error
	// GetCredential returns Idemix credential associated with the specified revocation
	// handle
	GetCredential(revocationHandle string) (*CredRecord, error)
	// GetCredentialsByID returns Idemix credentials associated with the specified
	// enrollment ID
	GetCredentialsByID(id string) ([]CredRecord, error)
	// GetRevokedCredentials returns revoked credentials
	GetRevokedCredentials() ([]CredRecord, error)
}

// CredentialAccessor implements IdemixCredDBAccessor interface
type CredentialAccessor struct {
	level int
	db    db.FabricCADB
}

// NewCredentialAccessor returns a new CredentialAccessor.
func NewCredentialAccessor(db db.FabricCADB, level int) CredDBAccessor {
	ac := new(CredentialAccessor)
	ac.db = db
	ac.level = level
	return ac
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (ac *CredentialAccessor) SetDB(db db.FabricCADB) {
	ac.db = db
}

// InsertCredential puts a CredentialRecord into db.
func (ac *CredentialAccessor) InsertCredential(cr CredRecord) error {
	log.Debug("DB: Insert Credential")
	err := ac.checkDB()
	if err != nil {
		return err
	}
	cr.Level = ac.level
	res, err := ac.db.NamedExec("InsertCredential", InsertCredentialSQL, cr)
	if err != nil {
		return errors.Wrap(err, "Failed to insert credential into datastore")
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return errors.New("Failed to insert the credential record; no rows affected")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to affect 1 entry in credentials table but affected %d",
			numRowsAffected)
	}

	return err
}

// GetCredentialsByID gets a CredentialRecord indexed by id.
func (ac *CredentialAccessor) GetCredentialsByID(id string) ([]CredRecord, error) {
	log.Debugf("DB: Get credentials by ID '%s'", id)
	err := ac.checkDB()
	if err != nil {
		return nil, err
	}
	crs := []CredRecord{}
	err = ac.db.Select("GetCredentialsByID", &crs, fmt.Sprintf(ac.db.Rebind(SelectCredentialByIDSQL), sqlstruct.Columns(CredRecord{})), id)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get credentials for identity '%s' from datastore", id)
	}

	return crs, nil
}

// GetCredential gets a CredentialRecord indexed by revocationHandle.
func (ac *CredentialAccessor) GetCredential(revocationHandle string) (*CredRecord, error) {
	log.Debugf("DB: Get credential by revocation handle '%s'", revocationHandle)
	err := ac.checkDB()
	if err != nil {
		return nil, err
	}
	cr := &CredRecord{}
	err = ac.db.Select("GetCredential", cr, fmt.Sprintf(ac.db.Rebind(SelectCredentialSQL), sqlstruct.Columns(CredRecord{})), revocationHandle)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get credential associated with revocation handle '%s' from datastore", revocationHandle)
	}

	return cr, nil
}

// GetRevokedCredentials returns revoked certificates
func (ac *CredentialAccessor) GetRevokedCredentials() ([]CredRecord, error) {
	err := ac.checkDB()
	if err != nil {
		return nil, err
	}
	crs := []CredRecord{}
	err = ac.db.Select("GetRevokedCredentials", &crs, fmt.Sprintf(ac.db.Rebind(SelectRevokedCredentialSQL), sqlstruct.Columns(CredRecord{})))
	if err != nil {
		return crs, errors.Wrap(err, "Failed to get revoked credentials from datastore")
	}
	return crs, nil
}

func (ac *CredentialAccessor) checkDB() error {
	if ac.db == nil || reflect.ValueOf(ac.db).IsNil() {
		return errors.New("Database is not set")
	}
	return nil
}
