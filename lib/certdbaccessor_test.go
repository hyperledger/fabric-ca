/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/mocks"
	"github.com/hyperledger/fabric-ca/lib/server/certificaterequest"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestGetCertificatesDB(t *testing.T) {
	os.RemoveAll("getCertDBTest")
	defer os.RemoveAll("getCertDBTest")
	log.Level = log.LevelDebug

	level := &dbutil.Levels{
		Affiliation: 1,
		Identity:    1,
		Certificate: 1,
	}
	mockOperationsServer := &mocks.OperationsServer{}
	fakeCounter := &metricsfakes.Counter{}
	fakeCounter.WithReturns(fakeCounter)
	mockOperationsServer.NewCounterReturns(fakeCounter)
	fakeHistogram := &metricsfakes.Histogram{}
	fakeHistogram.WithReturns(fakeHistogram)
	mockOperationsServer.NewHistogramReturns(fakeHistogram)
	srv := &Server{
		Operations: mockOperationsServer,
		levels:     level,
	}
	ca, err := newCA("getCertDBTest/config.yaml", &CAConfig{}, srv, false)
	util.FatalError(t, err, "Failed to get CA")

	populateCertificatesTable(t, ca)

	certReq := getCertReq("testCertificate1", "", "", false, false, nil, nil, nil, nil)
	rows, err := ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err := readRows(rows)
	assert.Equal(t, "testCertificate1", certs[0].Subject.CommonName)

	certReq = getCertReq("", "1111", "", false, false, nil, nil, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, big.NewInt(1111), certs[0].SerialNumber)

	certReq = getCertReq("", "", "9876", false, false, nil, nil, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 2, len(certs))
	assert.Equal(t, []byte("9876"), certs[0].AuthorityKeyId)

	certReq = getCertReq("", "", "", true, false, nil, nil, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 5, len(certs))

	certReq = getCertReq("", "", "", false, true, nil, nil, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 6, len(certs))

	certReq = getCertReq("", "1111", "", false, false, nil, nil, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "dept1")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 1, len(certs))
	assert.Equal(t, "testCertificate1", certs[0].Subject.CommonName)

	certReq = getCertReq("", "", "9876AB", false, false, nil, nil, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 1, len(certs))
	assert.Equal(t, "testCertificate3", certs[0].Subject.CommonName)

	revokedStart := time.Date(2018, time.January, 1, 0, 0, 0, 0, time.UTC)
	certReq = getCertReq("", "", "", false, false, &revokedStart, nil, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 1, len(certs))
	assert.Equal(t, "revoked1", certs[0].Subject.CommonName)

	revokedEnd := time.Date(2018, time.March, 1, 0, 0, 0, 0, time.UTC)
	certReq = getCertReq("", "", "", false, false, nil, &revokedEnd, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 2, len(certs))

	revokedStart = time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC)
	revokedEnd = time.Date(2017, time.August, 1, 0, 0, 0, 0, time.UTC)
	certReq = getCertReq("", "", "", false, false, &revokedStart, &revokedEnd, nil, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 1, len(certs))
	assert.Equal(t, "revoked2", certs[0].Subject.CommonName)

	expiredStart := time.Date(2018, time.March, 2, 0, 0, 0, 0, time.UTC)
	certReq = getCertReq("", "", "", false, false, nil, nil, &expiredStart, nil)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 6, len(certs))

	dur, err := time.ParseDuration("+100h")
	expiredEnd := time.Now().Add(dur).UTC()
	certReq = getCertReq("", "", "", false, false, nil, nil, nil, &expiredEnd)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 7, len(certs))

	expiredStart = time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC)
	expiredEnd = time.Date(2018, time.March, 1, 0, 0, 0, 0, time.UTC)
	certReq = getCertReq("", "", "", false, false, nil, nil, &expiredStart, &expiredEnd)
	rows, err = ca.certDBAccessor.GetCertificates(certReq, "")
	assert.NoError(t, err, "Failed to get certificates from database")
	certs, err = readRows(rows)
	assert.Equal(t, 1, len(certs))
	assert.Equal(t, "expire1", certs[0].Subject.CommonName)
}

func readRows(rows *sqlx.Rows) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for rows.Next() {
		var cert certPEM
		err := rows.StructScan(&cert)
		if err != nil {
			return nil, errors.Errorf("Failed to get read row: %s", err)
		}

		block, rest := pem.Decode([]byte(cert.PEM))
		if block == nil || len(rest) > 0 {
			return nil, errors.New("Certificate decoding error")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, certificate)
	}

	return certs, nil
}

func populateCertificatesTable(t *testing.T, ca *CA) {
	var err error

	dur, err := time.ParseDuration("+100h")
	util.FatalError(t, err, "Failed to parse duration '+100h'")
	futureTime := time.Now().Add(dur).UTC()

	ca.registry.InsertUser(&cadbuser.Info{
		Name:        "testCertificate1",
		Affiliation: "dept1",
	})
	// Active Certs
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1111",
		AKI:    "9876",
		Expiry: futureTime,
	}, "testCertificate1", ca)
	util.FatalError(t, err, "Failed to insert certificate with serial/AKI")

	ca.registry.InsertUser(&cadbuser.Info{
		Name:        "testCertificate2",
		Affiliation: "dept1",
	})
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1112",
		AKI:    "9876",
		Expiry: futureTime,
	}, "testCertificate2", ca)
	util.FatalError(t, err, "Failed to insert certificate with serial/AKI")

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1132",
		AKI:    "9876ab",
		Expiry: futureTime,
	}, "testCertificate3", ca)
	util.FatalError(t, err, "Failed to insert certificate with revocation date")

	// Expired
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1121",
		AKI:    "98765",
		Expiry: time.Date(2018, time.March, 1, 0, 0, 0, 0, time.UTC),
	}, "expire1", ca)
	util.FatalError(t, err, "Failed to insert certificate with expiration date")

	// Not Expired
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1122",
		AKI:    "98765",
		Expiry: futureTime,
	}, "expire2", ca)
	util.FatalError(t, err, "Failed to insert certificate with expiration date")

	// Revoked
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial:    "1131",
		AKI:       "98765",
		Expiry:    futureTime,
		RevokedAt: time.Date(2018, time.February, 15, 0, 0, 0, 0, time.UTC),
	}, "revoked1", ca)
	util.FatalError(t, err, "Failed to insert certificate with revocation date")

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial:    "1132",
		AKI:       "98765",
		Expiry:    futureTime,
		RevokedAt: time.Date(2017, time.February, 15, 0, 0, 0, 0, time.UTC),
	}, "revoked2", ca)
	util.FatalError(t, err, "Failed to insert certificate with revocation date")
}

func testInsertCertificate(req *certdb.CertificateRecord, id string, ca *CA) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Errorf("Failed to generate private key: %s", err)
	}

	serial := new(big.Int)
	serial.SetString(req.Serial, 10) //base 10

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: id,
		},
		SerialNumber:   serial,
		AuthorityKeyId: []byte(req.AKI),
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	var record = &db.CertRecord{
		ID: id,
		CertificateRecord: certdb.CertificateRecord{
			Serial:    req.Serial,
			AKI:       req.AKI,
			CALabel:   req.CALabel,
			Status:    req.Status,
			Reason:    req.Reason,
			Expiry:    req.Expiry.UTC(),
			RevokedAt: req.RevokedAt.UTC(),
			PEM:       string(cert),
		},
	}

	db := ca.GetDB()
	res, err := db.NamedExec("", insertSQL, record)
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

func getCertReq(id, serial, aki string, notrevoked, notexpired bool, revokedTimeStart, revokedTimeEnd, expiredTimeStart, expiredTimeEnd *time.Time) *certificaterequest.Impl {
	return &certificaterequest.Impl{
		ID:               id,
		SerialNumber:     serial,
		Aki:              aki,
		Notexpired:       notexpired,
		Notrevoked:       notrevoked,
		ExpiredTimeStart: expiredTimeStart,
		ExpiredTimeEnd:   expiredTimeEnd,
		RevokedTimeStart: revokedTimeStart,
		RevokedTimeEnd:   revokedTimeEnd,
	}
}
