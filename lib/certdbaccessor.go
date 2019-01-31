/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/log"
	cr "github.com/hyperledger/fabric-ca/lib/server/certificaterequest"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	cadb "github.com/hyperledger/fabric-ca/lib/server/db"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
	"github.com/pkg/errors"
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

// CertDBAccessor implements certdb.Accessor interface.
type CertDBAccessor struct {
	level    int
	accessor certdb.Accessor
	db       cadb.FabricCADB
}

// NewCertDBAccessor returns a new Accessor.
func NewCertDBAccessor(db cadb.FabricCADB, level int) *CertDBAccessor {
	return &CertDBAccessor{
		db:       db,
		accessor: certsql.NewAccessor(db.(*cadb.DB).DB.(*sqlx.DB)),
		level:    level,
	}
}

func (d *CertDBAccessor) checkDB() error {
	if d.db == nil {
		return errors.New("Database is not set")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *CertDBAccessor) SetDB(db *db.DB) {
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

	record := &db.CertRecord{
		ID:    id,
		Level: d.level,
		CertificateRecord: certdb.CertificateRecord{
			Serial:    serial,
			AKI:       aki,
			CALabel:   cr.CALabel,
			Status:    cr.Status,
			Reason:    cr.Reason,
			Expiry:    cr.Expiry.UTC(),
			RevokedAt: cr.RevokedAt.UTC(),
			PEM:       cr.PEM,
		},
	}

	res, err := d.db.NamedExec("InsertCertificate", insertSQL, record)
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
func (d *CertDBAccessor) GetCertificatesByID(id string) (crs []db.CertRecord, err error) {
	log.Debugf("DB: Get certificate by ID (%s)", id)
	err = d.checkDB()
	if err != nil {
		return nil, err
	}

	err = d.db.Select("GetCertificatesByID", &crs, fmt.Sprintf(d.db.Rebind(selectSQLbyID), sqlstruct.Columns(db.CertRecord{})), id)
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
		return nil, dbutil.GetError(err, "certificate")
	}

	return crs, nil
}

// GetCertificateWithID gets a CertificateRecord indexed by serial and returns user too.
func (d *CertDBAccessor) GetCertificateWithID(serial, aki string) (crs db.CertRecord, err error) {
	log.Debugf("DB: Get certificate by serial (%s) and aki (%s)", serial, aki)

	err = d.checkDB()
	if err != nil {
		return crs, err
	}

	err = d.db.Get("GetCertificatesByID", &crs, fmt.Sprintf(d.db.Rebind(selectSQL), sqlstruct.Columns(db.CertRecord{})), serial, aki)
	if err != nil {
		return crs, dbutil.GetError(err, "Certificate")
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
	err = d.db.Select("GetRevokedCertificates", &crs, fmt.Sprintf(d.db.Rebind(revokedSQL),
		sqlstruct.Columns(certdb.CertificateRecord{})), args...)
	if err != nil {
		return crs, dbutil.GetError(err, "Certificate")
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
func (d *CertDBAccessor) RevokeCertificatesByID(id string, reasonCode int) (crs []db.CertRecord, err error) {
	log.Debugf("DB: Revoke certificate by ID (%s)", id)

	err = d.checkDB()
	if err != nil {
		return nil, err
	}

	var record = new(db.CertRecord)
	record.ID = id
	record.Reason = reasonCode

	err = d.db.Select("RevokeCertificatesByID", &crs, d.db.Rebind("SELECT * FROM certificates WHERE (id = ? AND status != 'revoked')"), id)
	if err != nil {
		return nil, err
	}

	_, err = d.db.NamedExec("RevokeCertificatesByID", updateRevokeSQL, record)
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

// GetCertificates returns based on filter parameters certificates
func (d *CertDBAccessor) GetCertificates(req cr.CertificateRequest, callersAffiliation string) (*sqlx.Rows, error) {
	log.Debugf("DB: Get Certificates")

	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	whereConds := []string{}
	args := []interface{}{}

	getCertificateSQL := "SELECT certificates.pem FROM certificates" // Base SQL query for getting certificates

	// If caller's does not have root affiliation need to filter certificates based on affiliations of identities the
	// caller is allowed to see
	if callersAffiliation != "" {
		getCertificateSQL = "SELECT certificates.pem FROM certificates INNER JOIN users ON users.id = certificates.id"

		whereConds = append(whereConds, "(users.affiliation = ? OR users.affiliation LIKE ?)")
		args = append(args, callersAffiliation)
		args = append(args, callersAffiliation+".%")
	}

	// Apply further filters based on inputs
	if req.GetID() != "" {
		whereConds = append(whereConds, "certificates.id = ?")
		args = append(args, req.GetID())
	}
	if req.GetSerial() != "" {
		serial := strings.TrimLeft(strings.ToLower(req.GetSerial()), "0")
		whereConds = append(whereConds, "certificates.serial_number = ?")
		args = append(args, serial)
	}
	if req.GetAKI() != "" {
		aki := strings.TrimLeft(strings.ToLower(req.GetAKI()), "0")
		whereConds = append(whereConds, "certificates.authority_key_identifier = ?")
		args = append(args, aki)
	}

	if req.GetNotExpired() { // If notexpired is set to true, only return certificates that are not expired (expiration dates beyond the current time)
		whereConds = append(whereConds, "certificates.expiry >= ?")
		currentTime := time.Now().UTC()
		args = append(args, currentTime)
	} else {
		// If either expired start time or end time is not nil, formulate the appropriate query parameters. If end is not nil and start is nil
		// get all certificates that have an expiration date before the end date. If end is nil and start is not nil, get all certificates that
		// have expiration date after the start date.
		expiredTimeStart := req.GetExpiredTimeStart()
		expiredTimeEnd := req.GetExpiredTimeEnd()
		if expiredTimeStart != nil || expiredTimeEnd != nil {
			if expiredTimeStart != nil {
				whereConds = append(whereConds, "certificates.expiry >= ?")
				args = append(args, expiredTimeStart)
			} else {
				whereConds = append(whereConds, "certificates.expiry >= ?")
				args = append(args, time.Time{})
			}
			if expiredTimeEnd != nil {
				whereConds = append(whereConds, "certificates.expiry <= ?")
				args = append(args, expiredTimeEnd)
			}
		}
	}

	if req.GetNotRevoked() { // If notrevoked is set to true, only return certificates that are not revoked (revoked date is set to zero time)
		whereConds = append(whereConds, "certificates.revoked_at = ?")
		args = append(args, time.Time{})
	} else {
		// If either revoked start time or end time is not nil, formulate the appropriate query parameters. If end is not nil and start is nil
		// get all certificates that have an revocation date before the end date. If end is nil and start is not nil, get all certificates that
		// have revocation date after the start date.
		revokedTimeStart := req.GetRevokedTimeStart()
		revokedTimeEnd := req.GetRevokedTimeEnd()
		if revokedTimeStart != nil || revokedTimeEnd != nil {
			if revokedTimeStart != nil {
				whereConds = append(whereConds, "certificates.revoked_at >= ?")
				args = append(args, revokedTimeStart)
			} else {
				whereConds = append(whereConds, "certificates.revoked_at > ?")
				args = append(args, time.Time{})
			}
			if revokedTimeEnd != nil {
				whereConds = append(whereConds, "certificates.revoked_at <= ?")
				args = append(args, revokedTimeEnd)
			}
		}
	}

	if len(whereConds) > 0 {
		whereClause := strings.Join(whereConds, " AND ")
		getCertificateSQL = getCertificateSQL + " WHERE (" + whereClause + ")"
	}
	getCertificateSQL = getCertificateSQL + ";"

	log.Debugf("Executing get certificates query: %s, with args: %s", getCertificateSQL, args)
	rows, err := d.db.Queryx("GetCertificates", d.db.Rebind(getCertificateSQL), args...)
	if err != nil {
		return nil, dbutil.GetError(err, "Certificate")
	}

	return rows, nil
}
