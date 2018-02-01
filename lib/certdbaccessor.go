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

package lib

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/certdb"
	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/kisielk/sqlstruct"

	"github.com/jmoiron/sqlx"
)

const (
	insertSQL = `
INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem, level)
	VALUES (:id, :serial_number, :authority_key_identifier, :ca_label, :status, :reason, :expiry, :revoked_at, :pem, :level);`

	selectSQLbyID = `
SELECT %s FROM certificates
WHERE (id = ?);`

	selectSQL = `
SELECT %s FROM certificates
WHERE (serial_number = ? AND authority_key_identifier = ?);`

	updateRevokeSQL = `
UPDATE certificates
SET status='revoked', revoked_at=CURRENT_TIMESTAMP, reason=:reason
WHERE (id = :id AND status != 'revoked');`

	deleteCertificatebyID = `
DELETE FROM certificates
		WHERE (ID = ?);`
)

// CertRecord extends CFSSL CertificateRecord by adding an enrollment ID to the record
type CertRecord struct {
	ID    string `db:"id"`
	Level int    `db:"level"`
	certdb.CertificateRecord
}

// CertDBAccessor implements certdb.Accessor interface.
type CertDBAccessor struct {
	level    int
	accessor certdb.Accessor
	db       *sqlx.DB
}

// NewCertDBAccessor returns a new Accessor.
func NewCertDBAccessor(db *sqlx.DB, level int) *CertDBAccessor {
	cffslAcc := new(CertDBAccessor)
	cffslAcc.db = db
	cffslAcc.accessor = certsql.NewAccessor(db)
	cffslAcc.level = level
	return cffslAcc
}

func (d *CertDBAccessor) checkDB() error {
	if d.db == nil {
		return errors.New("Database is not set")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *CertDBAccessor) SetDB(db *sqlx.DB) {
	d.db = db
}

// InsertCertificate puts a CertificateRecord into db.
func (d *CertDBAccessor) InsertCertificate(cr certdb.CertificateRecord) error {

	log.Debug("DB: Insert Certificate")

	err := d.checkDB()
	if err != nil {
		return err
	}
	id, err := util.GetEnrollmentIDFromPEM([]byte(cr.PEM))
	if err != nil {
		return err
	}

	ip := new(big.Int)
	ip.SetString(cr.Serial, 10) //base 10

	serial := util.GetSerialAsHex(ip)
	aki := strings.TrimLeft(cr.AKI, "0")

	log.Debugf("Saved serial number as hex %s", serial)

	var record = new(CertRecord)
	record.ID = id
	record.Serial = serial
	record.AKI = aki
	record.CALabel = cr.CALabel
	record.Status = cr.Status
	record.Reason = cr.Reason
	record.Expiry = cr.Expiry.UTC()
	record.RevokedAt = cr.RevokedAt.UTC()
	record.PEM = cr.PEM
	record.Level = d.level

	res, err := d.db.NamedExec(insertSQL, record)
	if err != nil {
		return errors.Wrap(err, "Failed to insert record into database")
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return errors.New("Failed to insert the certificate record; no rows affected")
	}

	if numRowsAffected != 1 {
		return errors.Errorf("Expected to affect 1 entry in certificate database but affected %d",
			numRowsAffected)
	}

	return err
}

// GetCertificatesByID gets a CertificateRecord indexed by id.
func (d *CertDBAccessor) GetCertificatesByID(id string) (crs []CertRecord, err error) {
	log.Debugf("DB: Get certificate by ID (%s)", id)
	err = d.checkDB()
	if err != nil {
		return nil, err
	}

	err = d.db.Select(&crs, fmt.Sprintf(d.db.Rebind(selectSQLbyID), sqlstruct.Columns(CertRecord{})), id)
	if err != nil {
		return nil, err
	}

	return crs, nil
}

// GetCertificate gets a CertificateRecord indexed by serial.
func (d *CertDBAccessor) GetCertificate(serial, aki string) (crs []certdb.CertificateRecord, err error) {
	log.Debugf("DB: Get certificate by serial (%s) and aki (%s)", serial, aki)
	crs, err = d.accessor.GetCertificate(serial, aki)
	if err != nil {
		return nil, err
	}

	return crs, nil
}

// GetCertificateWithID gets a CertificateRecord indexed by serial and returns user too.
func (d *CertDBAccessor) GetCertificateWithID(serial, aki string) (crs CertRecord, err error) {
	log.Debugf("DB: Get certificate by serial (%s) and aki (%s)", serial, aki)

	err = d.checkDB()
	if err != nil {
		return crs, err
	}

	err = d.db.Get(&crs, fmt.Sprintf(d.db.Rebind(selectSQL), sqlstruct.Columns(CertRecord{})), serial, aki)
	if err != nil {
		return crs, getError(err, "Certificate")
	}

	return crs, nil
}

// GetUnexpiredCertificates gets all unexpired certificate from db.
func (d *CertDBAccessor) GetUnexpiredCertificates() (crs []certdb.CertificateRecord, err error) {
	crs, err = d.accessor.GetUnexpiredCertificates()
	if err != nil {
		return nil, err
	}
	return crs, err
}

// GetRevokedCertificates returns revoked certificates
func (d *CertDBAccessor) GetRevokedCertificates(expiredAfter, expiredBefore, revokedAfter, revokedBefore time.Time) ([]certdb.CertificateRecord, error) {
	log.Debugf("DB: Get revoked certificates that were revoked after %s and before %s that are expired after %s and before %s",
		revokedAfter, revokedBefore, expiredAfter, expiredBefore)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}
	var crs []certdb.CertificateRecord
	revokedSQL := "SELECT %s FROM certificates WHERE (WHERE_CLAUSE);"
	whereConds := []string{"status='revoked' AND expiry > ? AND revoked_at > ?"}
	args := []interface{}{expiredAfter, revokedAfter}
	if !expiredBefore.IsZero() {
		whereConds = append(whereConds, "expiry < ?")
		args = append(args, expiredBefore)
	}
	if !revokedBefore.IsZero() {
		whereConds = append(whereConds, "revoked_at < ?")
		args = append(args, revokedBefore)
	}
	whereClause := strings.Join(whereConds, " AND ")
	revokedSQL = strings.Replace(revokedSQL, "WHERE_CLAUSE", whereClause, 1)
	err = d.db.Select(&crs, fmt.Sprintf(d.db.Rebind(revokedSQL),
		sqlstruct.Columns(certdb.CertificateRecord{})), args...)
	if err != nil {
		return crs, getError(err, "Certificate")
	}
	return crs, nil
}

// GetRevokedAndUnexpiredCertificates returns revoked and unexpired certificates
func (d *CertDBAccessor) GetRevokedAndUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	crs, err := d.accessor.GetRevokedAndUnexpiredCertificates()
	if err != nil {
		return nil, err
	}
	return crs, err
}

// GetRevokedAndUnexpiredCertificatesByLabel returns revoked and unexpired certificates matching the label
func (d *CertDBAccessor) GetRevokedAndUnexpiredCertificatesByLabel(label string) ([]certdb.CertificateRecord, error) {
	crs, err := d.accessor.GetRevokedAndUnexpiredCertificatesByLabel(label)
	if err != nil {
		return nil, err
	}
	return crs, err
}

// RevokeCertificatesByID updates all certificates for a given ID and marks them revoked.
func (d *CertDBAccessor) RevokeCertificatesByID(id string, reasonCode int) (crs []CertRecord, err error) {
	log.Debugf("DB: Revoke certificate by ID (%s)", id)

	err = d.checkDB()
	if err != nil {
		return nil, err
	}

	var record = new(CertRecord)
	record.ID = id
	record.Reason = reasonCode

	err = d.db.Select(&crs, d.db.Rebind("SELECT * FROM certificates WHERE (id = ? AND status != 'revoked')"), id)
	if err != nil {
		return nil, err
	}

	_, err = d.db.NamedExec(updateRevokeSQL, record)
	if err != nil {
		return nil, err
	}

	return crs, err
}

// RevokeCertificate updates a certificate with a given serial number and marks it revoked.
func (d *CertDBAccessor) RevokeCertificate(serial, aki string, reasonCode int) error {
	log.Debugf("DB: Revoke certificate by serial (%s) and aki (%s)", serial, aki)

	err := d.accessor.RevokeCertificate(serial, aki, reasonCode)
	return err
}

// InsertOCSP puts a new certdb.OCSPRecord into the db.
func (d *CertDBAccessor) InsertOCSP(rr certdb.OCSPRecord) error {
	return d.accessor.InsertOCSP(rr)
}

// GetOCSP retrieves a certdb.OCSPRecord from db by serial.
func (d *CertDBAccessor) GetOCSP(serial, aki string) (ors []certdb.OCSPRecord, err error) {
	return d.accessor.GetOCSP(serial, aki)
}

// GetUnexpiredOCSPs retrieves all unexpired certdb.OCSPRecord from db.
func (d *CertDBAccessor) GetUnexpiredOCSPs() (ors []certdb.OCSPRecord, err error) {
	return d.accessor.GetUnexpiredOCSPs()
}

// UpdateOCSP updates a ocsp response record with a given serial number.
func (d *CertDBAccessor) UpdateOCSP(serial, aki, body string, expiry time.Time) error {
	return d.accessor.UpdateOCSP(serial, aki, body, expiry)
}

// UpsertOCSP update a ocsp response record with a given serial number,
// or insert the record if it doesn't yet exist in the db
func (d *CertDBAccessor) UpsertOCSP(serial, aki, body string, expiry time.Time) error {
	return d.accessor.UpsertOCSP(serial, aki, body, expiry)
}
