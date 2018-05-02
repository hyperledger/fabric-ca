/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"reflect"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/pkg/errors"

	"github.com/kisielk/sqlstruct"
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
	RevocationHandle int       `db:"revocation_handle"`
	Cred             string    `db:"cred"`
	CALabel          string    `db:"ca_label"`
	Status           string    `db:"status"`
	Reason           int       `db:"reason"`
	Expiry           time.Time `db:"expiry"`
	RevokedAt        time.Time `db:"revoked_at"`
	Level            int       `db:"level"`
}

// CredDBAccessor is the accessor for credentials database table
type CredDBAccessor interface {
	// InsertCredential inserts specified Idemix credential record into database
	InsertCredential(cr CredRecord) error
	// GetCredential returns Idemix credential associated with the specified revocation
	// handle
	GetCredential(revocationHandle string) (*CredRecord, error)
	// GetCredentialsByID returns Idemix credentials associated with the specified
	// enrollment ID
	GetCredentialsByID(id string) ([]CredRecord, error)
}

// CredentialAccessor implements IdemixCredDBAccessor interface
type CredentialAccessor struct {
	level int
	db    dbutil.FabricCADB
}

// NewCredentialAccessor returns a new CredentialAccessor.
func NewCredentialAccessor(db dbutil.FabricCADB, level int) *CredentialAccessor {
	ac := new(CredentialAccessor)
	ac.db = db
	ac.level = level
	return ac
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (ac *CredentialAccessor) SetDB(db dbutil.FabricCADB) {
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
	res, err := ac.db.NamedExec(InsertCredentialSQL, cr)
	if err != nil {
		return errors.Wrap(err, "Failed to insert credential into database")
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
	err = ac.db.Select(&crs, fmt.Sprintf(ac.db.Rebind(SelectCredentialByIDSQL), sqlstruct.Columns(CredRecord{})), id)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get credentials for identity '%s' from database", id)
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
	err = ac.db.Select(cr, fmt.Sprintf(ac.db.Rebind(SelectCredentialSQL), sqlstruct.Columns(CredRecord{})), revocationHandle)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to get credential associated with revocation handle '%s' from database", revocationHandle)
	}

	return cr, nil
}

func (ac *CredentialAccessor) checkDB() error {
	if ac.db == nil || reflect.ValueOf(ac.db).IsNil() {
		return errors.New("Database is not set")
	}
	return nil
}
