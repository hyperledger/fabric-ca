/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/cloudflare/cfssl/config"
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
	var err error
	// Enroll a user that will be used for subsequent certificate commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = command.RunMain([]string{cmdName, "reenroll", "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d"})
	assert.NoError(t, err, "Failed to get certificates")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "-30d::+15d"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-30d::-15d"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "2018-01-01::2018-01-31"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "2018-01-01::2018-01-31"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "2018-01-01T01:00:00Z::2018-01-31T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "2018-01-01T01:00:00Z::2018-01-31T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "now::+15d"})
	assert.NoError(t, err, "Failed to parse a expiration date range using 'now'")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-15d::now"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now'")
}

func TestGetCertificatesTimeInput(t *testing.T) {
	os.RemoveAll(clientHome)
	defer os.RemoveAll(clientHome)

	var err error

	client := lib.GetTestClient(defaultServerPort, clientHome)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	negativeTimeTestCases(t, admin)
	positiveTimeTestCases(t, admin)
}

func negativeTimeTestCases(t *testing.T, admin *lib.Identity) {
	req := &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			EndTime: "-30y",
		},
	}
	err := admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for expiration end time")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-30y",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for revocation end time")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-IOd",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-30.5",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "2018-01-01T00:00:00",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")
}

func positiveTimeTestCases(t *testing.T, admin *lib.Identity) {
	req := &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "+30d",
		},
	}
	err := admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse correct time")

	req = &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "2018-01-01",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse date/time without the time")

	req = &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "2018-01-01T00:00:00Z",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse date/time")
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
		log.Fatalf("Failed to create certificate: %s", err)
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	var record = new(lib.CertRecord)
	record.ID = id
	record.Serial = req.Serial
	record.AKI = req.AKI
	record.CALabel = req.CALabel
	record.Status = req.Status
	record.Reason = req.Reason
	record.Expiry = req.Expiry.UTC()
	record.RevokedAt = req.RevokedAt.UTC()
	record.PEM = string(cert)

	db := srv.CA.GetDB()
	res, err := db.NamedExec(`INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem, level)
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
