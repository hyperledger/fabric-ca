/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	cmdName    = "fabric-ca-client"
	clientHome = "clientHome"
)

var (
	defaultServer          *lib.Server
	defaultServerPort      = 7054
	defaultServerEnrollURL = fmt.Sprintf("http://admin:adminpw@localhost:%d", defaultServerPort)
	defaultServerHomeDir   = "defaultServerDir"
	storeCertsDir          = "/tmp/testCerts"
)

func TestMain(m *testing.M) {
	var err error

	metadata.Version = "1.1.0"

	os.RemoveAll(defaultServerHomeDir)
	defaultServer, err = getDefaultServer()
	if err != nil {
		log.Errorf("Failed to get instance of server: %s", err)
		os.Exit(1)
	}

	err = defaultServer.Start()
	if err != nil {
		log.Errorf("Failed to start server: %s", err)
		os.Exit(1)
	}

	rc := m.Run()

	err = defaultServer.Stop()
	if err != nil {
		log.Errorf("Failed to stop server: %s, integration test results: %d", err, rc)
		os.Exit(1)
	}

	os.RemoveAll(defaultServerHomeDir)
	os.RemoveAll(storeCertsDir)
	os.Exit(rc)
}

func TestListCertificateCmdNegative(t *testing.T) {
	var err error
	// Remove default client home location to remove any existing enrollment information
	os.RemoveAll(filepath.Dir(util.GetDefaultConfigFile("fabric-ca-client")))

	// Command should fail if caller has not yet enrolled
	err = command.RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Enrollment information does not exist", "Should have failed to call command, if caller has not yet enrolled")

	// Enroll a user that will be used for subsequent certificate commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	// Test with --revocation flag
	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-30d:-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, only one ':' specified need to specify two '::'")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "30d::-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on starting duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "+30d::15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on ending duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "+30d::+15y"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, invalid duration type (y)")

	// Test with --expiration flag
	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "-30d:-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, only one ':' specified need to specify two '::'")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "30d::-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on starting duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "+30d::15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on ending duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "1/30/18::2/14/2018"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, using slashes instead of dashes in time format")
}

func TestListCertificateCmdPositive(t *testing.T) {
	populateCertificatesTable(t, defaultServer)

	var err error
	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "+30d::+15d", "--notexpired"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, --expiration and --notexpired together")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-30d::-10d", "--notrevoked"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, --revocation and --notrevoked together")

	// Enroll a user that will be used for subsequent certificate commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d"})
	assert.NoError(t, err, "Failed to get certificates")

	result, err := captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--id", "expire1"})
	assert.NoError(t, err, "Failed to get certificate for an id")
	assert.Contains(t, result, "expire1")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--serial", "1111"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation duration")
	assert.Contains(t, result, "Serial Number: 1111")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--aki", "9876"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation duration")
	assert.Contains(t, result, "Serial Number: 1111")
	assert.Contains(t, result, "Serial Number: 1112")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--serial", "1112", "--aki", "9876"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation duration")
	assert.Contains(t, result, "Serial Number: 1112")
	assert.NotContains(t, result, "Serial Number: 1111")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--id", "testCertificate3", "--aki", "9876AB"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation duration")
	assert.Contains(t, result, "1113")
	assert.Contains(t, result, "testCertificate3")
	assert.NotContains(t, result, "testCertificate1")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--id", "expire1", "--expiration", "2018-01-01::2018-03-05"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")
	assert.Contains(t, result, "expire1")
	assert.NotContains(t, result, "expire3")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--id", "revoked2", "--revocation", "2017-01-01::2017-12-31"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")
	assert.Contains(t, result, "revoked2")
	assert.NotContains(t, result, "revoked3")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--expiration", "2018-03-01T00:00:00Z::2018-03-03T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")
	assert.Contains(t, result, "Serial Number: 1121")
	assert.NotContains(t, result, "Serial Number: 1123")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--revocation", "2017-02-01T01:00:00Z::2017-02-20T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")
	assert.Contains(t, result, "Serial Number: 1132")
	assert.NotContains(t, result, "Serial Number: 1131")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--expiration", "now::+101h"})
	assert.NoError(t, err, "Failed to parse a expiration date range using 'now'")
	assert.Contains(t, result, "Serial Number: 1123")
	assert.NotContains(t, result, "Serial Number: 1121")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--revocation", "-15d::now"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now'")
	assert.Contains(t, result, "Serial Number: 1131")
	assert.NotContains(t, result, "Serial Number: 1111")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--expiration", "now::"})
	assert.NoError(t, err, "Failed to parse a expiration date range using 'now' and empty end date")
	assert.NotContains(t, result, "Serial Number: 1121")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--expiration", "::now"})
	assert.NoError(t, err, "Failed to parse a expiration date range using 'now' and empty start date")
	assert.Contains(t, result, "Serial Number: 1121")
	assert.Contains(t, result, "Serial Number: 1122")
	assert.Contains(t, result, "Serial Number: 1124")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--expiration", "::now", "--notrevoked"})
	assert.NoError(t, err, "Failed to parse a expiration date range using 'now' and empty start date")
	assert.Contains(t, result, "Serial Number: 1121")
	assert.Contains(t, result, "Serial Number: 1122")
	assert.NotContains(t, result, "Serial Number: 1124")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--revocation", "2018-02-01T01:00:00Z::"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now' and empty end date")
	assert.Contains(t, result, "1131")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--revocation", "::now"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now' and empty start date")
	assert.Contains(t, result, "Serial Number: 1131")
	assert.Contains(t, result, "Serial Number: 1132")
	assert.Contains(t, result, "Serial Number: 1124")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--revocation", "::now", "--notexpired"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now' and empty start date")
	assert.Contains(t, result, "Serial Number: 1131")
	assert.Contains(t, result, "Serial Number: 1132")
	assert.NotContains(t, result, "Serial Number: 1124")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--notrevoked", "--notexpired"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now' and empty start date")
	assert.Contains(t, result, "Serial Number: 1111")
	assert.Contains(t, result, "Serial Number: 1112")
	assert.Contains(t, result, "Serial Number: 1113")
	assert.Contains(t, result, "Serial Number: 1123")
	assert.NotContains(t, result, "Serial Number: 1121")
	assert.NotContains(t, result, "Serial Number: 1122")
	assert.NotContains(t, result, "Serial Number: 1124")
	assert.NotContains(t, result, "Serial Number: 1131")
	assert.NotContains(t, result, "Serial Number: 1132")
	assert.NotContains(t, result, "Serial Number: 1133")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "-d", "--id", "fakeID"})
	assert.NoError(t, err, "Should not error if the ID does not exist")
	assert.Contains(t, result, "No results returned")

	result, err = captureCLICertificatesOutput(command.RunMain, []string{cmdName, "certificate", "list", "--id", "expire1", "--store", storeCertsDir})
	assert.NoError(t, err, "Should not error if the ID does not exist")
	assert.Equal(t, true, util.FileExists(filepath.Join(storeCertsDir, "expire1-1.pem")))
	assert.Equal(t, true, util.FileExists(filepath.Join(storeCertsDir, "expire1-2.pem")))
	assert.Contains(t, result, "Serial Number: 1121")
	assert.Contains(t, result, "Serial Number: 1124")
}

func populateCertificatesTable(t *testing.T, srv *lib.Server) {
	var err error

	dur, err := time.ParseDuration("+100h")
	util.FatalError(t, err, "Failed to parse duration '+100h'")
	futureTime := time.Now().Add(dur).UTC()

	dur, err = time.ParseDuration("-72h")
	util.FatalError(t, err, "Failed to parse duration '-72h'")
	pastTime := time.Now().Add(dur).UTC()

	// Active Certs
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1111",
		AKI:    "9876",
		Expiry: futureTime,
	}, "testCertificate1", srv)
	util.FatalError(t, err, "Failed to insert certificate with serial/AKI")

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1112",
		AKI:    "9876",
		Expiry: futureTime,
	}, "testCertificate2", srv)
	util.FatalError(t, err, "Failed to insert certificate with serial/AKI")

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1113",
		AKI:    "9876ab",
		Expiry: futureTime,
	}, "testCertificate3", srv)
	util.FatalError(t, err, "Failed to insert certificate with serial/AKI")

	// Expired
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1121",
		AKI:    "98765",
		Expiry: time.Date(2018, time.March, 1, 0, 0, 0, 0, time.UTC),
	}, "expire1", srv)
	util.FatalError(t, err, "Failed to insert certificate with expiration date")

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1122",
		AKI:    "98765",
		Expiry: time.Date(2018, time.March, 1, 0, 0, 0, 0, time.UTC),
	}, "expire3", srv)
	util.FatalError(t, err, "Failed to insert certificate with expiration date")

	// Not Expired
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1123",
		AKI:    "98765",
		Expiry: futureTime,
	}, "expire2", srv)
	util.FatalError(t, err, "Failed to insert certificate with expiration date")

	// Expired and Revoked
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial:    "1124",
		AKI:       "98765",
		Expiry:    time.Date(2018, time.March, 1, 0, 0, 0, 0, time.UTC),
		RevokedAt: pastTime,
	}, "expire1", srv)
	util.FatalError(t, err, "Failed to insert certificate with expiration date")

	// Revoked
	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial:    "1131",
		AKI:       "98765",
		Expiry:    futureTime,
		RevokedAt: pastTime,
	}, "revoked1", srv)
	util.FatalError(t, err, "Failed to insert certificate with revocation date")

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial:    "1132",
		AKI:       "98765",
		Expiry:    futureTime,
		RevokedAt: time.Date(2017, time.February, 15, 0, 0, 0, 0, time.UTC),
	}, "revoked2", srv)
	util.FatalError(t, err, "Failed to insert certificate with revocation date")

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial:    "1133",
		AKI:       "98765",
		Expiry:    futureTime,
		RevokedAt: time.Date(2017, time.February, 15, 0, 0, 0, 0, time.UTC),
	}, "revoked3", srv)
	util.FatalError(t, err, "Failed to insert certificate with revocation date")
}

func captureCLICertificatesOutput(f func(args []string) error, args []string) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout = w
	err = f(args)
	if err != nil {
		return "", err
	}
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String(), nil
}

func TestRevokeWithColons(t *testing.T) {
	var err error

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "11aa22bb",
		AKI:    "33cc44dd",
	}, "testingRevoke", defaultServer)
	util.FatalError(t, err, "Failed to insert certificate with serial/AKI")

	// Enroll a user that will be used for subsequent revoke commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = command.RunMain([]string{cmdName, "register", "-u", defaultServerEnrollURL, "--id.name", "testingRevoke", "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = command.RunMain([]string{cmdName, "revoke", "-s", "11:AA:22:bb", "-a", "33:Cc:44:DD", "-d"})
	assert.NoError(t, err, "Failed to revoke certificate, when serial number and AKI contained colons")
}

func getDefaultServer() (*lib.Server, error) {
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"org2":      []string{"dept1"},
		"org1":      nil,
		"org2dept1": nil,
	}
	profiles := map[string]*config.SigningProfile{
		"tls": &config.SigningProfile{
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth", "key agreement"},
			ExpiryString: "8760h",
		},
		"ca": &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "8760h",
			CAConstraint: config.CAConstraint{
				IsCA:       true,
				MaxPathLen: 0,
			},
		},
	}
	defaultProfile := &config.SigningProfile{
		Usage:        []string{"cert sign"},
		ExpiryString: "8760h",
	}
	srv := &lib.Server{
		Config: &lib.ServerConfig{
			Port:  defaultServerPort,
			Debug: true,
		},
		CA: lib.CA{
			Config: &lib.CAConfig{
				Intermediate: lib.IntermediateCA{
					ParentServer: lib.ParentServer{
						URL: "",
					},
				},
				Affiliations: affiliations,
				Registry: lib.CAConfigRegistry{
					MaxEnrollments: -1,
				},
				Signing: &config.Signing{
					Profiles: profiles,
					Default:  defaultProfile,
				},
				Version: "1.1.0", // The default test server/ca should use the latest version
			},
		},
		HomeDir: defaultServerHomeDir,
	}
	// The bootstrap user's affiliation is the empty string, which
	// means the user is at the affiliation root
	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		return nil, err
	}
	return srv, nil
}

func testInsertCertificate(req *certdb.CertificateRecord, id string, srv *lib.Server) error {
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
		return err
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	record := &db.CertRecord{
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

	db := srv.CA.GetDB()
	res, err := db.NamedExec("", `INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem, level)
	VALUES (:id, :serial_number, :authority_key_identifier, :ca_label, :status, :reason, :expiry, :revoked_at, :pem, :level);`, record)

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
