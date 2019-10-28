/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/attrmgr"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/lib/server/db/sqlite"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

const (
	testdataDir          = "homeDir"
	mspDir               = "../../../testdata/msp"
	myhost               = "hostname"
	certfile             = "ec.pem"
	keyfile              = "ec-key.pem"
	tlsCertFile          = "tls_server-cert.pem"
	tlsKeyFile           = "tls_server-key.pem"
	rootCert             = "root.pem"
	tlsClientCertFile    = "tls_client-cert.pem"
	tlsClientCertExpired = "expiredcert.pem"
	tlsClientKeyFile     = "tls_client-key.pem"
	tdDir                = "../../../testdata"
	dbName               = "fabric-ca-server.db"
	serverPort           = 7090
	rootCertEnvVar       = "FABRIC_CA_CLIENT_TLS_CERTFILES"
	clientKeyEnvVar      = "FABRIC_CA_CLIENT_TLS_CLIENT_KEYFILE"
	clientCertEnvVar     = "FABRIC_CA_CLIENT_TLS_CLIENT_CERTFILE"
	moptionDir           = "moption-test"
	clientCMD            = "fabric-ca-client"
	crlExpiry            = time.Hour * 240 // 10 days
)

const jsonConfig = `{
  "URL": "http://localhost:8888",
  "tls": {
    "enabled": false,
    "certfiles": null,
    "client": {
      "certfile": null,
      "keyfile": null
    }
  },
  "csr": {
    "cn": "admin",
    "names": [
      {
        "C": "US",
        "ST": "North Carolina",
        "L": null,
        "O": "Hyperledger",
        "OU": "Fabric"
      }
    ],
    "hosts": [
      "charente"
    ],
    "ca": {
      "pathlen": null,
      "pathlenzero": null,
      "expiry": null
    }
  },
  "id": {
    "name": null,
    "type": null,
    "group": null,
    "attributes": [
      {
        "name": null,
        "value": null
      }
    ]
  },
  "enrollment": {
    "hosts": null,
    "profile": null,
    "label": null
  }
}`

var (
	defYaml       string
	fabricCADB    = path.Join(tdDir, dbName)
	srv           *lib.Server
	serverURL     = fmt.Sprintf("http://localhost:%d", serverPort)
	enrollURL     = fmt.Sprintf("http://admin:adminpw@localhost:%d", serverPort)
	enrollURL1    = fmt.Sprintf("http://admin2:adminpw2@localhost:%d", serverPort)
	tlsServerURL  = fmt.Sprintf("https://localhost:%d", serverPort)
	tlsEnrollURL  = fmt.Sprintf("https://admin:adminpw@localhost:%d", serverPort)
	tlsEnrollURL1 = fmt.Sprintf("https://admin2:adminpw2@localhost:%d", serverPort)
	testYaml      = path.Join(tdDir, "test.yaml")
)

type TestData struct {
	input []string // input
}

func TestMain(m *testing.M) {
	metadata.Version = "1.1.0"
	os.Exit(m.Run())
}

func TestNoArguments(t *testing.T) {
	err := RunMain([]string{cmdName})
	if err == nil {
		assert.Error(t, errors.New("Should have resulted in an error as no agruments provided"))
	}
}
func TestExtraArguments(t *testing.T) {
	errCases := []TestData{
		{[]string{cmdName, "enroll", "extraArg", "extraArg2"}},
		{[]string{cmdName, "reenroll", "extraArg", "extraArg2"}},
		{[]string{cmdName, "register", "extraArg", "extraArg2"}},
		{[]string{cmdName, "revoke", "extraArg", "extraArg2"}},
		{[]string{cmdName, "getcacert", "extraArg", "extraArg2"}},
	}

	for _, e := range errCases {
		extraArgErrorTest(&e, t)
	}
}

// TestCreateDefaultConfigFile test to make sure default config file gets generated correctly
func TestCreateDefaultConfigFile(t *testing.T) {
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml)

	err := RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-m", myhost})
	if err == nil {
		t.Errorf("No server running, should have failed")
	}

	fileBytes, err := ioutil.ReadFile(defYaml)
	if err != nil {
		t.Error(err)
	}

	configFile := string(fileBytes)

	if !strings.Contains(configFile, "localhost:7090") {
		t.Error("Failed to update default config file with url")
	}

	if !strings.Contains(configFile, myhost) {
		t.Error("Failed to update default config file with host name")
	}

	os.Remove(defYaml)
}

func TestClientCommandsNoTLS(t *testing.T) {
	os.Remove(fabricCADB)

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	srv.HomeDir = tdDir
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "hyperledger")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin3", "adminpw3", "company1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	aff := make(map[string]interface{})
	aff["hyperledger"] = []string{"org1", "org2", "org3"}
	aff["company1"] = []string{"dept1"}
	aff["company2"] = []string{}

	srv.CA.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}
	defer srv.Stop()

	testConfigFileTypes(t)
	testGetCACert(t)
	testEnroll(t)
	testProfiling(t)
	testRegisterConfigFile(t)
	testRegisterEnvVar(t)
	testRegisterCommandLine(t, srv)
	testRevoke(t)
	testBogus(t)
	testAffiliation(t)
}

func TestEnroll(t *testing.T) {
	t.Log("Testing Enroll")
	adminHome := filepath.Join(tdDir, "enrolladminhome")

	// Remove admin home directory if it exists
	err := os.RemoveAll(adminHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s: %s", adminHome, err)
	}

	// Remove admin home directory that this test is going to create before
	// exiting the test case
	defer os.RemoveAll(adminHome)

	srv := setupEnrollTest(t)

	// Cleanup before exiting the test case
	defer stopAndCleanupServer(t, srv)

	// Enroll with -u parameter. Value of the -u parameter is used as server URL
	err = RunMain([]string{cmdName, "enroll", "-d", "-u", enrollURL, "-H", adminHome})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	// Enroll without -u parameter, should fail as the server URL is picked
	// from the configuration file but userid and password are not part of the
	// URL
	err = RunMain([]string{cmdName, "enroll", "-d", "-H", adminHome})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	// Remove admin home
	err = os.RemoveAll(adminHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s: %s", adminHome, err)
	}

	// Enroll without -u parameter but with FABRIC_CA_CLIENT_URL env variable
	// Default client configuration file will be generated. Value of the
	// FABRIC_CA_CLIENT_URL env variable is used as server URL
	os.Setenv("FABRIC_CA_CLIENT_URL", enrollURL1)
	defer os.Unsetenv("FABRIC_CA_CLIENT_URL")
	err = RunMain([]string{cmdName, "enroll", "-d", "-H", adminHome})
	if err != nil {
		t.Errorf("client enroll with FABRIC_CA_CLIENT_URL env variable failed: %s", err)
	}

	// Enroll without -u parameter but with FABRIC_CA_CLIENT_URL env variable
	// Existing client configuration file will be used. Value of the
	// FABRIC_CA_CLIENT_URL env variable is used as server URL
	err = RunMain([]string{cmdName, "enroll", "-d", "-H", adminHome})
	if err != nil {
		t.Errorf("client enroll with FABRIC_CA_CLIENT_URL env variable failed: %s", err)
	}
}

// Tests expiration of enrollment certificate is not after the expiration
// of the CA certificate that issued the enrollment certificate.
func TestEnrollmentCertExpiry(t *testing.T) {
	certExpiryTestDir := "certexpirytest"
	os.RemoveAll(certExpiryTestDir)
	defer os.RemoveAll(certExpiryTestDir)

	exprStr := "720h"
	srv := startServerWithCustomExpiry(path.Join(certExpiryTestDir, "rootServer"), serverPort, exprStr, t)
	defer srv.Stop()

	adminHome := filepath.Join(tdDir, "certexpadminhome")
	err := os.RemoveAll(adminHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s: %s", adminHome, err)
	}
	defer os.RemoveAll(adminHome)

	// Enroll admin identity
	err = RunMain([]string{cmdName, "enroll", "-d", "-u", enrollURL, "-H", adminHome})
	if err != nil {
		t.Errorf("Enrollment of admin failed: %s", err)
	}

	certfile := filepath.Join(adminHome, "msp/signcerts/cert.pem")
	cacertFile := filepath.Join(adminHome, "msp/cacerts/localhost-"+strconv.Itoa(serverPort)+".pem")

	certbytes, err := ioutil.ReadFile(certfile)
	assert.NoError(t, err, "Failed to read the cert from the file %s", certfile)
	cert, err := lib.BytesToX509Cert(certbytes)
	assert.NoError(t, err, "Failed to convert bytes to certificate")

	certbytes, err = ioutil.ReadFile(cacertFile)
	assert.NoError(t, err, "Failed to read the cert from the file %s", cacertFile)
	cacert, err := lib.BytesToX509Cert(certbytes)
	assert.NoError(t, err, "Failed to convert bytes to certificate")

	y, m, d := cacert.NotAfter.Date()
	dur, _ := time.ParseDuration(exprStr)
	y1, m1, d1 := time.Now().UTC().Add(dur).Date()
	assert.Equal(t, y1, y, "CA cert's expiration year is not as expected")
	assert.Equal(t, m1, m, "CA cert's expiration month is not as expected")
	assert.Equal(t, d1, d, "CA cert's expiration day is not as expected")

	assert.False(t, cert.NotAfter.After(cacert.NotAfter),
		"Enrollment certificate expires after CA cert")
}

// Test cases for gencrl command
func TestGenCRL(t *testing.T) {
	t.Log("Testing GenCRL")
	adminHome := filepath.Join(tdDir, "gencrladminhome")

	// Remove admin home directory if it exists
	err := os.RemoveAll(adminHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s: %s", adminHome, err)
	}

	// Remove admin home directory that this test is going to create before
	// exiting the test case
	defer os.RemoveAll(adminHome)

	// Set up for the test case
	srv := setupGenCRLTest(t, adminHome)

	// Cleanup before exiting the test case
	defer stopAndCleanupServer(t, srv)

	// Error case 1: gencrl command should fail when called without enrollment info
	tmpHome := filepath.Join(os.TempDir(), "gencrlhome")
	defer os.RemoveAll(tmpHome)
	prvHome := os.Getenv(homeEnvVar)
	defer os.Setenv(homeEnvVar, prvHome)

	os.Setenv(homeEnvVar, tmpHome)
	err = RunMain([]string{cmdName, "gencrl"})
	assert.Error(t, err, "gencrl should have failed when called without enrollment information")

	os.Setenv(homeEnvVar, adminHome)

	// Register, enroll and revoke two users using admin identity
	client := &lib.Client{
		Config:  &lib.ClientConfig{URL: fmt.Sprintf("http://localhost:%d", serverPort)},
		HomeDir: adminHome,
	}
	admin, err := client.LoadMyIdentity()
	if err != nil {
		t.Fatalf("Failed to load admin identity: %s", err)
	}

	var revokedCertSerials []*big.Int

	// Success cases
	// success case 1: there are no revoked certs
	err = RunMain([]string{cmdName, "gencrl"})
	assert.NoError(t, err, "gencrl failed")
	checkCRL(t, admin.GetClient(), revokedCertSerials)

	revokedCertSerials = registerAndRevokeUsers(t, admin, 2)

	// success case 2: gencrl invoked without any arguments
	err = RunMain([]string{cmdName, "gencrl"})
	assert.NoError(t, err, "gencrl failed")
	checkCRL(t, admin.GetClient(), revokedCertSerials)

	// success case 3: gencrl invoked with --revokedafter argument but not --revokedbefore
	pastTime := time.Now().UTC().Add(time.Hour * -1).Format(time.RFC3339)
	err = RunMain([]string{cmdName, "gencrl", "--revokedafter", pastTime})
	assert.NoError(t, err, "gencrl failed")
	checkCRL(t, admin.GetClient(), revokedCertSerials)

	// success case 4: gencrl invoked with --revokedbefore argument but not --revokedafter
	futureTime := time.Now().UTC().Add(time.Hour * 1).Format(time.RFC3339)
	err = RunMain([]string{cmdName, "gencrl", "--revokedbefore", futureTime})
	assert.NoError(t, err, "gencrl failed")
	checkCRL(t, admin.GetClient(), revokedCertSerials)

	// success case 5: gencrl invoked with --expirebefore, --revokedbefore and --revokedafter args
	expTime := time.Now().UTC().Add(time.Hour * 3).Format(time.RFC3339)
	err = RunMain([]string{cmdName, "gencrl", "--revokedafter", pastTime,
		"--revokedbefore", futureTime, "--expirebefore", expTime})
	assert.NoError(t, err, "gencrl failed")
	checkCRL(t, admin.GetClient(), revokedCertSerials)

	// success case 6: gencrl invoked with --expireafter, --revokedbefore and --revokedafter args
	err = RunMain([]string{cmdName, "gencrl", "--expireafter", time.Now().UTC().Format(time.RFC3339),
		"--revokedafter", pastTime, "--revokedbefore", futureTime})
	assert.NoError(t, err, "gencrl failed")
	checkCRL(t, admin.GetClient(), revokedCertSerials)

	// success case 6: gencrl invoked with all args
	err = RunMain([]string{cmdName, "gencrl", "--expireafter", time.Now().UTC().Format(time.RFC3339),
		"--expirebefore", time.Now().Add(time.Hour * 24 * 365 * 2).UTC().Format(time.RFC3339),
		"--revokedafter", pastTime, "--revokedbefore", futureTime})
	assert.NoError(t, err, "gencrl failed")
	checkCRL(t, admin.GetClient(), revokedCertSerials)

	// Error cases
	// Error case 2: should fail when invoked with invalid --revokedafter arg
	err = RunMain([]string{cmdName, "gencrl", "--revokedafter", "foo"})
	assert.Error(t, err, "gencrl should have failed when --revokedafter value is not a timestamp")

	// Error case 3: should fail when invoked with invalid --revokedafter arg
	err = RunMain([]string{cmdName, "gencrl", "--revokedafter", "Mon Jan 2 15:04:05 -0700 MST 2006"})
	assert.Error(t, err, "gencrl should have failed when --revokedafter value is not in RFC339 format")

	// Error case 4: should fail when invoked with invalid --revokedbefore arg
	err = RunMain([]string{cmdName, "gencrl", "--revokedbefore", "bar"})
	assert.Error(t, err, "gencrl should have failed when --revokedbefore value is not a timestamp")

	// Error case 5: should fail when invoked with invalid --revokedbefore arg
	err = RunMain([]string{cmdName, "gencrl", "--revokedbefore", "Sat Mar 7 11:06:39 PST 2015"})
	assert.Error(t, err, "gencrl should have failed when --revokedbefore value is not in RFC339 format")

	// Error case 6: should fail when invoked with revokeafter value is greater (comes after) than revokedbefore
	err = RunMain([]string{cmdName, "gencrl", "--revokedafter", "2017-09-13T16:39:57-08:00",
		"--revokedbefore", "2017-09-13T15:39:57-08:00"})
	assert.Error(t, err, "gencrl should have failed when --revokedafter value is greater than --revokedbefore")

	// Error case 7: should fail when invoked with invalid --expireafter arg
	err = RunMain([]string{cmdName, "gencrl", "--expireafter", "foo"})
	assert.Error(t, err, "gencrl should have failed when --expireafter value is not a timestamp")

	// Error case 8: should fail when invoked with invalid --expireafter arg
	err = RunMain([]string{cmdName, "gencrl", "--expireafter", "Mon Jan 2 15:04:05 -0700 MST 2006"})
	assert.Error(t, err, "gencrl should have failed when --expireafter value is not in RFC339 format")

	// Error case 9: should fail when invoked with invalid --expirebefore arg
	err = RunMain([]string{cmdName, "gencrl", "--expirebefore", "bar"})
	assert.Error(t, err, "gencrl should have failed when --expirebefore value is not a timestamp")

	// Error case 10: should fail when invoked with invalid --expirebefore arg
	err = RunMain([]string{cmdName, "gencrl", "--expirebefore", "Sat Mar 7 11:06:39 PST 2015"})
	assert.Error(t, err, "gencrl should have failed when --expirebefore value is not in RFC339 format")

	// Error case 11: should fail when invoked with expireafter value is greater (comes after) than expirebefore
	err = RunMain([]string{cmdName, "gencrl", "--expireafter", "2017-09-13T16:39:57-08:00",
		"--expirebefore", "2017-09-13T15:39:57-08:00"})
	assert.Error(t, err, "gencrl should have failed when --expireafter value is greater than --expirebefore")
}

// Test role based access control
func TestRBAC(t *testing.T) {
	// Variable initialization
	curDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %s", err)
	}
	testDir := path.Join(curDir, "testDir")
	testUser := "testUser"
	testPass := "testUserpw"
	adminUserHome := path.Join(testDir, "adminUser")
	adminUserConfig := path.Join(adminUserHome, "config.yaml")
	testUserHome := path.Join(testDir, "testUser")
	testUserConfig := path.Join(testUserHome, "config.yaml")

	// Start with a clean test dir
	os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)

	// Start the server
	server := startServer(testDir, 7054, "", t)
	defer server.Stop()

	// Negative test case to try to enroll with an badly formatted attribute request
	err = RunMain([]string{
		cmdName, "enroll",
		"--enrollment.attrs", "foo,bar:zoo",
		"-c", adminUserConfig,
		"-u", "http://admin:adminpw@localhost:7054"})
	if err == nil {
		t.Error("enrollment with badly formatted attribute requests should fail")
	}

	// Enroll the admin
	err = RunMain([]string{
		cmdName, "enroll",
		"-c", adminUserConfig,
		"-u", "http://admin:adminpw@localhost:7054"})
	if err != nil {
		t.Fatalf("client enroll -u failed: %s", err)
	}

	// Negative test to add attribute with invalid flag (foo)
	err = RunMain([]string{
		cmdName, "register", "-d",
		"-c", adminUserConfig,
		"--id.name", testUser,
		"--id.secret", testPass,
		"--id.type", "user",
		"--id.affiliation", "org1",
		"--id.attrs", "admin=true:foo"})
	if err == nil {
		t.Error("client register should have failed because of invalid attribute flag")
	}

	// Register test user with an attribute to be inserted in ecert by default
	err = RunMain([]string{
		cmdName, "register", "-d",
		"-c", adminUserConfig,
		"--id.name", testUser,
		"--id.secret", testPass,
		"--id.type", "user",
		"--id.affiliation", "org1",
		"--id.attrs", "admin=true:ecert,foo=bar"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	// Enroll the test user with no attribute requests and make sure the
	// resulting ecert has the default attributes and no extra
	err = RunMain([]string{
		cmdName, "enroll", "-d",
		"-c", testUserConfig,
		"-u", fmt.Sprintf("http://%s:%s@localhost:7054", testUser, testPass)})
	if err != nil {
		t.Fatalf("client enroll of test user failed: %s", err)
	}
	checkAttrsInCert(t, testUserHome, "admin", "true", "foo")

	// Enroll the test user with attribute requests and make sure the
	// resulting ecert has the requested attributes only
	err = RunMain([]string{
		cmdName, "enroll", "-d",
		"--enrollment.attrs", "foo,unknown:opt",
		"-c", testUserConfig,
		"-u", fmt.Sprintf("http://%s:%s@localhost:7054", testUser, testPass)})
	if err != nil {
		t.Fatalf("client enroll of test user failed: %s", err)
	}
	checkAttrsInCert(t, testUserHome, "foo", "bar", "admin")

	// Negative test case to request an attribute that the identity doesn't have
	err = RunMain([]string{
		cmdName, "enroll", "-d",
		"--enrollment.attrs", "unknown",
		"-c", testUserConfig,
		"-u", fmt.Sprintf("http://%s:%s@localhost:7054", testUser, testPass)})
	if err == nil {
		t.Error("enrollment request with unknown required attribute should fail")
	}

	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestIdentityCmd(t *testing.T) {
	idWithNoAttrs := lib.CAConfigIdentity{
		Name:           "userWithNoAttrs",
		Pass:           "userWithNoAttrs",
		Affiliation:    "org1",
		MaxEnrollments: 10,
		Type:           "client",
	}
	server := setupIdentityCmdTest(t, idWithNoAttrs)
	defer stopAndCleanupServer(t, server)

	err := RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	util.FatalError(t, err, "Failed to enroll user")

	err = RunMain([]string{cmdName, "register", "--id.name", "test user"})
	util.FatalError(t, err, "Failed to register user")

	result, err := captureOutput(RunMain, []string{
		cmdName, "identity", "list"})
	assert.NoError(t, err, "Failed to get all ids")
	assert.Contains(t, result, "admin")
	assert.Contains(t, result, "test user")

	result, err = captureOutput(RunMain, []string{
		cmdName, "identity", "list", "--id", "test user"})
	assert.NoError(t, err, "Failed to get id 'test user'")
	assert.Contains(t, result, "test user")

	err = RunMain([]string{
		cmdName, "identity", "add"})
	if assert.Error(t, err, "Should have failed, no arguments provided") {
		assert.Contains(t, err.Error(), "Identity name is required")
	}

	err = RunMain([]string{
		cmdName, "identity", "modify"})
	if assert.Error(t, err, "Should have failed, no arguments provided") {
		assert.Contains(t, err.Error(), "Identity name is required")
	}

	err = RunMain([]string{
		cmdName, "identity", "remove"})
	if assert.Error(t, err, "Should have failed, no arguments provided") {
		assert.Contains(t, err.Error(), "Identity name is required")
	}

	err = RunMain([]string{
		cmdName, "identity", "add", "user1", "badinput"})
	if assert.Error(t, err, "Should have failed, too many arguments") {
		assert.Contains(t, err.Error(), "Unknown argument")
	}

	err = RunMain([]string{
		cmdName, "identity", "modify", "user1", "badinput"})
	if assert.Error(t, err, "Should have failed, too many arguments") {
		assert.Contains(t, err.Error(), "Unknown argument")
	}

	err = RunMain([]string{
		cmdName, "identity", "remove", "user1", "badinput"})
	if assert.Error(t, err, "Should have failed, too many arguments") {
		assert.Contains(t, err.Error(), "Unknown argument")
	}

	err = RunMain([]string{
		cmdName, "identity", "add", "testuser", "--json", `{"type": "peer"}`, "--type", "peer"})
	if assert.Error(t, err, "Should have failed") {
		assert.Contains(t, err.Error(), "Can't use 'json' flag in conjunction with other flags")
	}

	err = RunMain([]string{
		cmdName, "identity", "add", "testuser", "--json", `{"type": "peer"}`, "--attrs", "hf.Revoker=true"})
	if assert.Error(t, err, "Should have failed") {
		assert.Contains(t, err.Error(), "Can't use 'json' flag in conjunction with other flags")
	}

	err = RunMain([]string{
		cmdName, "identity", "modify", "testuser", "--json", `{"type": "peer"}`, "--type", "peer"})
	if assert.Error(t, err, "Should have failed") {
		assert.Contains(t, err.Error(), "Can't use 'json' flag in conjunction with other flags")
	}

	err = RunMain([]string{
		cmdName, "identity", "modify", "testuser", "--json", `{"type": "peer"}`, "--affiliation", "org1"})
	if assert.Error(t, err, "Should have failed") {
		assert.Contains(t, err.Error(), "Can't use 'json' flag in conjunction with other flags")
	}

	// Add user using JSON
	err = RunMain([]string{
		cmdName, "identity", "add", "-d", "testuser1", "--json", `{"secret": "user1pw", "type": "user", "affiliation": "org1", "max_enrollments": 1, "attrs": [{"name": "hf.Revoker", "value": "false"},{"name": "hf.IntermediateCA", "value": "false"}]}`})
	assert.NoError(t, err, "Failed to add user 'testuser1'")

	err = RunMain([]string{
		cmdName, "identity", "add", "testuser1", "--json", `{"secret": "user1pw", "type": "user", "affiliation": "org1", "max_enrollments": 1, "attrs": [{"name:": "hf.Revoker", "value": "false"}]}`})
	assert.Error(t, err, "Should have failed to add same user twice")

	// Check that the secret got correctly configured
	err = RunMain([]string{
		cmdName, "enroll", "-u", "http://testuser1:user1pw@localhost:7090", "-d"})
	assert.NoError(t, err, "Failed to enroll user 'testuser2'")

	// Enroll admin back to use it credentials for next commands
	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	util.FatalError(t, err, "Failed to enroll user")

	// Add user using flags
	err = RunMain([]string{
		cmdName, "identity", "add", "testuser2", "--secret", "user2pw", "--type", "client", "--affiliation", ".", "--maxenrollments", "45", "--attrs", "hf.Revoker=true"})
	assert.NoError(t, err, "Failed to add user 'testuser2'")

	server.CA.Config.Registry.MaxEnrollments = 50
	// Test default max enrollment values for adding identity default to using CA's max enrollment value
	err = RunMain([]string{
		cmdName, "identity", "add", "testuser3"})
	assert.NoError(t, err, "Failed to add user 'testuser3'")

	// Check that the secret got correctly configured
	err = RunMain([]string{
		cmdName, "enroll", "-u", "http://testuser2:user2pw@localhost:7090", "-d"})
	assert.NoError(t, err, "Failed to enroll user 'testuser2'")

	// Enroll admin back to use it credentials for next commands
	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	util.FatalError(t, err, "Failed to enroll user")

	// modify user secret using flags
	err = RunMain([]string{
		cmdName, "identity", "modify", "testuser2", "--secret", "user2pw2"})
	assert.NoError(t, err, "Failed to add user 'testuser2'")

	// Modify user's secret, check if no other user attributes were modified
	userBforeModify, err := getUser(idWithNoAttrs.Name, server)
	if err != nil {
		t.Fatalf("Failed to read '%s' from the database", idWithNoAttrs.Name)
	}

	// modify user with no attrs
	err = RunMain([]string{
		cmdName, "identity", "modify", idWithNoAttrs.Name, "--secret", "user2pw2"})
	assert.NoError(t, err, "Failed to modify user "+idWithNoAttrs.Name)

	userAfterModify, err := getUser(idWithNoAttrs.Name, server)
	if err != nil {
		t.Fatalf("Failed to read '%s' from the database", idWithNoAttrs.Name)
	}
	assert.Equal(t, userBforeModify.GetType(), userAfterModify.GetType(),
		"User type must be same after user secret was modified")
	assert.Equal(t, cadbuser.GetAffiliation(userBforeModify),
		cadbuser.GetAffiliation(userAfterModify),
		"User affiliation must be same after user secret was modified")
	assert.Equal(t, userBforeModify.GetMaxEnrollments(), userAfterModify.GetMaxEnrollments(),
		"User max enrollments must be same after user secret was modified")

	origAttrs, err := userBforeModify.GetAttributes(nil)
	if err != nil {
		t.Fatalf("Failed to get attributes of the user '%s'", idWithNoAttrs.Name)
	}
	modAttrs, err := userAfterModify.GetAttributes(nil)
	if err != nil {
		t.Fatalf("Failed to get attributes of the modified user '%s'", idWithNoAttrs.Name)
	}
	assert.Equal(t, len(origAttrs), len(modAttrs),
		"User attributes must be same after user secret was modified")

	// Check that the secret got correctly configured
	err = RunMain([]string{
		cmdName, "enroll", "-u", "http://testuser2:user2pw2@localhost:7090", "-d"})
	assert.NoError(t, err, "Failed to enroll user 'testuser2'")

	// Enroll admin back to use it credentials for next commands
	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	util.FatalError(t, err, "Failed to enroll user")

	registry := server.CA.DBAccessor()
	user, err := registry.GetUser("testuser1", nil)
	util.FatalError(t, err, "Failed to get user 'testuser1'")

	_, err = user.GetAttribute("hf.IntermediateCA")
	assert.NoError(t, err, "Failed to get attribute")

	_, err = registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	// Modify value for hf.Revoker, add hf.Registrar.Roles, and delete hf.IntermediateCA attribute
	err = RunMain([]string{
		cmdName, "identity", "modify", "testuser1", "--type", "peer", "--affiliation", ".", "--attrs", "hf.Revoker=true,hf.Registrar.Roles=peer,hf.IntermediateCA="})
	assert.NoError(t, err, "Failed to modify user 'testuser1'")

	user, err = registry.GetUser("testuser1", nil)
	util.FatalError(t, err, "Failed to get user 'testuser1'")

	if user.GetType() != "peer" {
		t.Error("Failed to correctly modify user 'testuser1'")
	}
	affPath := cadbuser.GetAffiliation(user)
	if affPath != "" {
		t.Error("Failed to correctly modify user 'testuser1'")
	}
	attrs, err := user.GetAttributes(nil)
	assert.NoError(t, err, "Failed to get user attributes")
	attrMap := getAttrsMap(attrs)

	val := attrMap["hf.Revoker"]
	assert.Equal(t, "true", val.Value, "Failed to correctly modify attributes for user 'testuser1'")

	val = attrMap["hf.Registrar.Roles"]
	assert.Equal(t, "peer", val.Value, "Failed to correctly modify attributes for user 'testuser1'")

	_, found := attrMap["hf.IntermediateCA"]
	assert.False(t, found, "Failed to delete attribute 'hf.IntermediateCA'")

	err = RunMain([]string{
		cmdName, "identity", "remove", "testuser1"})
	assert.Error(t, err, "Should have failed, identity removal not allowed on server")

	user, err = registry.GetUser("testuser3", nil)
	util.FatalError(t, err, "Failed to get user 'testuser1'")
	assert.Equal(t, 50, user.GetMaxEnrollments())

	server.CA.Config.Cfg.Identities.AllowRemove = true

	err = RunMain([]string{
		cmdName, "identity", "remove", "testuser1"})
	assert.NoError(t, err, "Failed to remove user")
}

func TestAffiliationCmd(t *testing.T) {
	var err error

	// Start with a clean test dir
	os.RemoveAll("affiliation")
	defer os.RemoveAll("affiliation")

	// Start the server
	server := startServer("affiliation", 7090, "", t)
	defer server.Stop()

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	util.FatalError(t, err, "Failed to enroll user")

	result, err := captureOutput(RunMain, []string{cmdName, "affiliation", "list"})
	assert.NoError(t, err, "Failed to return all affiliations")
	assert.Equal(t, "affiliation: org1\n", result)

	err = RunMain([]string{cmdName, "affiliation", "list", "--affiliation", "org2"})
	assert.Error(t, err, "Should failed to get the requested affiliation, affiliation does not exist")

	err = RunMain([]string{
		cmdName, "affiliation", "add"})
	if assert.Error(t, err, "Should have failed, no arguments provided") {
		assert.Contains(t, err.Error(), "affiliation name is required")
	}

	err = RunMain([]string{
		cmdName, "affiliation", "modify"})
	if assert.Error(t, err, "Should have failed, no arguments provided") {
		assert.Contains(t, err.Error(), "affiliation name is required")
	}

	err = RunMain([]string{
		cmdName, "affiliation", "remove"})
	if assert.Error(t, err, "Should have failed, no arguments provided") {
		assert.Contains(t, err.Error(), "affiliation name is required")
	}

	err = RunMain([]string{
		cmdName, "affiliation", "add", "org3", "badinput"})
	if assert.Error(t, err, "Should have failed, too many arguments") {
		assert.Contains(t, err.Error(), "Unknown argument")
	}

	err = RunMain([]string{
		cmdName, "affiliation", "modify", "org3", "badinput"})
	if assert.Error(t, err, "Should have failed, too many arguments") {
		assert.Contains(t, err.Error(), "Unknown argument")
	}

	err = RunMain([]string{
		cmdName, "affiliation", "remove", "org3", "badinput"})
	if assert.Error(t, err, "Should have failed, too many arguments") {
		assert.Contains(t, err.Error(), "Unknown argument")
	}

	err = RunMain([]string{
		cmdName, "affiliation", "add", "org3"})
	assert.NoError(t, err, "Caller with root affiliation failed to add affiliation 'org3'")

	err = RunMain([]string{
		cmdName, "affiliation", "add", "org4.dept1.team", "--force"})
	assert.NoError(t, err, "Caller with root affiliation failed to add affiliation 'org4.dept1.team2'")

	server.CA.Config.Cfg.Affiliations.AllowRemove = true

	registry := server.CA.DBAccessor()

	err = RunMain([]string{
		cmdName, "affiliation", "remove", "org3"})
	assert.NoError(t, err, "Failed to remove affiliation")

	_, err = registry.GetAffiliation("org3")
	assert.Error(t, err, "Failed to remove 'org3' successfully")

	err = RunMain([]string{
		cmdName, "affiliation", "modify", "org1", "--name", "org3"})
	assert.NoError(t, err, "Failed to rename affiliation from 'org2' to 'org3'")

	_, err = registry.GetAffiliation("org3")
	assert.NoError(t, err, "Failed to rename 'org1' to 'org3' successfully")

	err = RunMain([]string{
		cmdName, "affiliation", "remove", "org4"})
	assert.Error(t, err, "Should have failed, no force argument provided and affiliation being deleted had sub-affiliations")

	// if previous test failed, don't bother with the next one
	if err != nil {
		err = RunMain([]string{
			cmdName, "affiliation", "remove", "org4", "--force"})
		assert.NoError(t, err, "Failed to remove affiliation with force argument")
	}
}

// Verify the certificate has attribute 'name' with a value of 'val'
// and does not have the 'missing' attribute.
func checkAttrsInCert(t *testing.T, home, name, val, missing string) {

	// Load the user's ecert
	cert, err := util.GetX509CertificateFromPEMFile(path.Join(home, "msp", "signcerts", "cert.pem"))
	if err != nil {
		t.Fatalf("Failed to load test user's cert: %s", err)
	}

	// Get the attributes from the cert
	attrs, err := attrmgr.New().GetAttributesFromCert(cert)
	if err != nil {
		t.Fatalf("Failed to get attributes from certificate: %s", err)
	}

	// Make sure the attribute is in the cert
	v, ok, err := attrs.Value(name)
	if err != nil {
		t.Fatalf("Failed to get '%s' attribute from cert: %s", name, err)
	}
	if !ok {
		t.Fatalf("The '%s' attribute was not found in the cert", name)
	}

	// Make sure the value of the attribute is as expected
	if v != val {
		t.Fatalf("The value of the '%s' attribute is '%s' rather than '%s'", name, v, val)
	}

	// Make sure the missing attribute was NOT found
	_, ok, err = attrs.Value(missing)
	if err != nil {
		t.Fatalf("Failed to get '%s' attribute from cert: %s", missing, err)
	}
	if ok {
		t.Fatalf("The '%s' attribute was found in the cert but should not be", missing)
	}
}

func testConfigFileTypes(t *testing.T) {
	t.Log("Testing config file types")

	// Viper supports file types:
	//    yaml, yml, json, hcl, toml, props, prop, properties, so
	// any other file type will result in an error. However, not all
	// these file types are suitable to represent fabric-ca
	// client/server config properties -- for example, props/prop/properties
	// file type
	err := RunMain([]string{cmdName, "enroll", "-u", enrollURL,
		"-c", "config/client-config.txt"})
	if err == nil {
		t.Errorf("Enroll command invoked with -c config/client-config.txt should have failed: %v",
			err.Error())
	}

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL,
		"-c", "config/client-config.mf"})
	if err == nil {
		t.Errorf("Enroll command invoked with -c config/client-config.mf should have failed: %v",
			err.Error())
	}

	fName := os.TempDir() + "/client-config.json"
	f, err := os.Create(fName)
	if err != nil {
		t.Fatalf("Unable to create json config file: %v", err.Error())
	}
	w := bufio.NewWriter(f)
	nb, err := w.WriteString(jsonConfig)
	if err != nil {
		t.Fatalf("Unable to write to json config file: %v", err.Error())
	}
	t.Logf("Wrote %d bytes to %s", nb, fName)
	w.Flush()

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL,
		"-c", fName})
	if err != nil {
		t.Errorf("Enroll command invoked with -c %s failed: %v",
			fName, err.Error())
	}
	os.RemoveAll("./config")
}

// TestGetCACert tests fabric-ca-client getcacert
func testGetCACert(t *testing.T) {
	t.Log("Testing getcacert command")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml) // Clean up any left over config file
	os.RemoveAll("msp")
	err := RunMain([]string{cmdName, "getcacert", "-d", "-u", serverURL})
	assert.NoError(t, err, "getcacert should not have failed")
	assert.True(t, util.FileExists(path.Dir(defYaml)+"/msp/IssuerPublicKey"), "IssuerPublicKey file should exist after getcacert call")

	err = RunMain([]string{cmdName, "getcacert", "-d", "-u", "http://localhost:9999"})
	if err == nil {
		t.Error("getcacert with bogus URL should have failed but did not")
	}

	err = RunMain([]string{cmdName, "getcacert", "-d"})
	if err == nil {
		t.Error("getcacert with no URL should have failed but did not")
	}

	err = RunMain([]string{cmdName, "getcacert", "Z"})
	if err == nil {
		t.Error("getcacert called with bogus argument, should have failed")
	}
	os.RemoveAll("cacerts")
	os.RemoveAll("msp")
	os.Remove(defYaml)
}

// TestEnroll tests fabric-ca-client enroll
func testEnroll(t *testing.T) {
	t.Log("Testing Enroll command")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.Remove(defYaml) // Clean up any left over config file

	// Negative test case, enroll command without username/password
	err := RunMain([]string{cmdName, "enroll", "-d"})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	err = RunMain([]string{cmdName, "enroll", "-d", "-u", enrollURL, "-M", filepath.Join(filepath.Dir(defYaml), "msp"), "--csr.keyrequest.algo", "badalgo"})
	assert.Error(t, err, "Incorrect key algo value, should fail")

	err = RunMain([]string{cmdName, "enroll", "-d", "-u", enrollURL, "-M", filepath.Join(filepath.Dir(defYaml), "msp"), "--csr.keyrequest.algo", "ecdsa", "--csr.keyrequest.size", "1234"})
	assert.Error(t, err, "Incorrect key size value, should fail")

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-M", filepath.Join(filepath.Dir(defYaml), "msp"), "--csr.keyrequest.algo", "ecdsa", "--csr.keyrequest.size", "256"})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	testReenroll(t)

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin2:adminpw2@localhost:7091"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7091) for server")
	}

	err = RunMain([]string{cmdName, "enroll", "Z"})
	if err == nil {
		t.Error("enroll called with bogus argument, should have failed")
	}
	os.Remove(defYaml)
}

// TestGencsr tests fabric-ca-client gencsr
func TestGencsr(t *testing.T) {
	t.Log("Testing gencsr CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.Remove(defYaml) // Clean up any left over config file

	mspDir := filepath.Join(filepath.Dir(defYaml), "msp")

	os.RemoveAll(mspDir)

	defer os.Remove(defYaml)

	err := RunMain([]string{cmdName, "gencsr", "--csr.cn", "identity", "--csr.names", "C=CA,O=Org1,OU=OU1", "-M", mspDir})
	if err != nil {
		t.Errorf("client gencsr failed: %s", err)
	}

	signcerts := path.Join(mspDir, "signcerts")
	assertFilesInDir(signcerts, 1, t)

	files, err := ioutil.ReadDir(signcerts)
	if err != nil {
		t.Fatalf("Failed to get number of files in directory '%s': %s", signcerts, err)
	}

	if files[0].Name() != "identity.csr" {
		t.Fatalf("Failed to find identity.csr in '%s': %s", signcerts, err)
	}

	err = RunMain([]string{cmdName, "gencsr", "--csr.cn", "identity", "--csr.names", "C=CA,O=Org1,FOO=BAR", "-M", mspDir})
	if err == nil {
		t.Error("Should have failed: Invalid CSR name")
	}

	err = RunMain([]string{cmdName, "gencsr", "--csr.cn", "identity", "--csr.names", "C:CA,O=Org1,OU=OU2", "-M", mspDir})
	if err == nil {
		t.Error("Should have failed: No '=' for name/value pair")
	}

	err = RunMain([]string{cmdName, "gencsr", "-c", defYaml, "--csr.names", "C=CA,O=Org1,OU=OU1", "-M", mspDir})
	if err == nil {
		t.Error("Should have failed: CSR CN not specified.")
	}
}

func TestDifferentKeySizeAlgos(t *testing.T) {
	config := `csr:
  cn: <<CN>>
  names:
    - C: US
      ST: "North Carolina"
      L:
      O: Hyperledger
      OU: Fabric
  keyrequest:
    algo: <<ALGO>>
    size: <<SIZE>>
  hosts:
   - hostname
`
	writeConfig := func(cn, algo string, size int, dir string) error {
		cfg := strings.Replace(config, "<<CN>>", cn, 1)
		cfg = strings.Replace(cfg, "<<ALGO>>", algo, 1)
		cfg = strings.Replace(cfg, "<<SIZE>>", strconv.Itoa(size), 1)
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
		fileName := filepath.Join(dir, "fabric-ca-client-config.yaml")
		err = ioutil.WriteFile(fileName, []byte(cfg), os.ModePerm)
		return err
	}

	testdata := []struct {
		algo                  string
		size                  int
		errorExpected         bool
		expectedSignatureAlgo x509.SignatureAlgorithm
	}{
		{"ecdsa", 256, false, x509.ECDSAWithSHA256},
		{"ecdsa", 384, false, x509.ECDSAWithSHA384},
		{"ecdsa", 521, true, x509.ECDSAWithSHA512},
		{"rsa", 2048, false, x509.SHA256WithRSA},
		{"rsa", 3072, false, x509.SHA384WithRSA},
		{"rsa", 4096, false, x509.SHA512WithRSA},
	}

	homeDir := filepath.Join(tdDir, "genCSRDiffKeyReqs")
	err := os.RemoveAll(homeDir)
	if err != nil {
		t.Fatalf("Failed to remove directory %s: %s", homeDir, err)
	}

	// Remove home directory that this test is going to create before
	// exiting the test case
	defer os.RemoveAll(homeDir)

	for _, data := range testdata {
		cn := "TestGenCSRWithDifferentKeyRequests" + data.algo + strconv.Itoa(data.size)
		err := writeConfig(cn, data.algo, data.size, homeDir)
		if err != nil {
			t.Fatalf("Failed to write client config file in the %s directory: %s", homeDir, err)
		}

		err = RunMain([]string{cmdName, "gencsr", "-H", homeDir})
		if !data.errorExpected {
			assert.NoError(t, err, "GenCSR called with %s algorithm and %d key size should not have failed", data.algo, data.size)
			csrFileName := cn + ".csr"
			csrBytes, rerr := ioutil.ReadFile(filepath.Join(homeDir, "msp/signcerts", csrFileName))
			assert.NoError(t, rerr, "Failed to read the generated CSR from the file %s:", csrFileName)

			block, _ := pem.Decode(csrBytes)
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				t.Errorf("Block type read from the CSR file %s is not of type certificate request", csrFileName)
			}
			certReq, perr := x509.ParseCertificateRequest(block.Bytes)
			assert.NoError(t, perr, "Failed to parse generated CSR")
			assert.Equal(t, data.expectedSignatureAlgo, certReq.SignatureAlgorithm, "Not expected signature algorithm in the CSR")
		} else {
			if assert.Errorf(t, err, "GenCSR called with %s algorithm and %d key size should have failed", data.algo, data.size) {
				assert.Contains(t, err.Error(), "Unsupported", "Not expected error message")
			}
		}
	}

	// Test enroll with ecdsa algorithm and 384 key size
	srv := setupGenCSRTest(t, homeDir)
	defer stopAndCleanupServer(t, srv)

	// Enroll admin
	err = RunMain([]string{cmdName, "enroll", "-H", homeDir, "-u", "http://admin:adminpw@localhost:7090"})
	if err != nil {
		t.Fatalf("Failed to enroll admin: %s", err)
	}
	certBytes, rerr1 := ioutil.ReadFile(filepath.Join(homeDir, "msp/signcerts/cert.pem"))
	if rerr1 != nil {
		t.Fatalf("Failed to read the enrollment certificate: %s", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("Block type read from the cert file is not of type certificate")
	}
	cert, perr1 := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, perr1, "Failed to parse enrollment certificate")
	assert.Equal(t, x509.ECDSAWithSHA384, cert.SignatureAlgorithm, "Not expected signature algorithm in the ecert")
}

// TestMOption tests to make sure that the key is stored in the correct
// directory when the "-M" option is used.
// This also ensures the intermediatecerts directory structure is populated
// since we enroll with an intermediate CA.
func TestMOption(t *testing.T) {
	os.RemoveAll(moptionDir)
	defer os.RemoveAll(moptionDir)
	rootCAPort := 7173
	rootServer := startServer(path.Join(moptionDir, "rootServer"), rootCAPort, "", t)
	if rootServer == nil {
		return
	}
	defer rootServer.Stop()
	rootCAURL := fmt.Sprintf("http://admin:adminpw@localhost:%d", rootCAPort)
	intCAPort := 7174
	intServer := startServer(path.Join(moptionDir, "intServer"), intCAPort, rootCAURL, t)
	if intServer == nil {
		return
	}
	defer intServer.Stop()
	homedir := path.Join(moptionDir, "client")
	mspdir := "msp2" // relative to homedir
	err := RunMain([]string{
		cmdName, "enroll",
		"-u", fmt.Sprintf("http://admin:adminpw@localhost:%d", intCAPort),
		"-c", path.Join(homedir, "config.yaml"),
		"-M", mspdir, "-d"})
	if err != nil {
		t.Fatalf("client enroll -u failed: %s", err)
	}
	assertFilesInDir(path.Join(homedir, mspdir, "keystore"), 1, t)
	assertFilesInDir(path.Join(homedir, mspdir, "cacerts"), 1, t)
	assertFilesInDir(path.Join(homedir, mspdir, "intermediatecerts"), 1, t)
	validCertsInDir(path.Join(homedir, mspdir, "cacerts"), path.Join(homedir, mspdir, "intermediatecerts"), t)
	_, err = ioutil.ReadDir(path.Join(homedir, mspdir, "tlscacerts"))
	assert.Error(t, err, "The MSP folder 'tlscacerts' should not exist")
	_, err = ioutil.ReadDir(path.Join(homedir, mspdir, "tlsintermediatecerts"))
	assert.Error(t, err, "The MSP folder 'tlsintermediatecerts' should not exist")

	homedir = path.Join(moptionDir, "client")
	mspdir = "msp3" // relative to homedir
	err = RunMain([]string{
		cmdName, "enroll",
		"-u", fmt.Sprintf("http://admin:adminpw@localhost:%d", intCAPort),
		"-c", path.Join(homedir, "config.yaml"),
		"-M", mspdir, "--enrollment.profile", "tls", "-d"})
	if err != nil {
		t.Fatalf("client enroll -u failed: %s", err)
	}
	assertFilesInDir(path.Join(homedir, mspdir, "keystore"), 1, t)
	assertFilesInDir(path.Join(homedir, mspdir, "tlscacerts"), 1, t)
	assertFilesInDir(path.Join(homedir, mspdir, "tlsintermediatecerts"), 1, t)
	validCertsInDir(path.Join(homedir, mspdir, "tlscacerts"), path.Join(homedir, mspdir, "tlsintermediatecerts"), t)
	assertFilesInDir(path.Join(homedir, mspdir, "cacerts"), 0, t)
	_, err = ioutil.ReadDir(path.Join(homedir, mspdir, "intermediatecerts"))
	assert.Error(t, err, "The MSP folder 'intermediatecerts' should not exist")

	// Test case: msp and home are in different paths
	// Enroll the bootstrap user and then register another user. Since msp
	// and home are in two different directory paths, registration should
	// not fail if -M option is not specified
	mspdir = os.TempDir() + "/msp-abs-test"
	homedir = os.TempDir() + "/msp-abs-test-home"
	defer os.RemoveAll(mspdir)
	defer os.RemoveAll(homedir)
	err = RunMain([]string{
		cmdName, "enroll",
		"-u", fmt.Sprintf("http://admin:adminpw@localhost:%d", intCAPort),
		"-H", homedir,
		"-M", mspdir, "-d"})
	if err != nil {
		t.Fatalf("client enroll -u failed: %s", err)
	}
	err = RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegisterForMoption",
		"--id.affiliation", "org1", "--id.type", "user", "-H", homedir})
	assert.NoError(t, err, "Register command should not fail even though -M option is not specified")
}

// Checks to see if root and intermediate certificates are correctly getting stored in their respective directories
func validCertsInDir(rootCertDir, interCertsDir string, t *testing.T) {
	files, err := ioutil.ReadDir(rootCertDir)
	file := files[0].Name()
	rootCertPath := filepath.Join(rootCertDir, file)
	rootcert, err := util.GetX509CertificateFromPEMFile(rootCertPath)
	assert.NoError(t, err, "Failed to read cert file")

	if !reflect.DeepEqual(rootcert.Subject, rootcert.Issuer) {
		t.Errorf("Not a valid root certificate '%s' stored in the '%s' directory", rootCertPath, filepath.Base(rootCertDir))
	}

	interCertPath := filepath.Join(interCertsDir, file)
	intercert, err := util.GetX509CertificateFromPEMFile(interCertPath)
	assert.NoError(t, err, "Failed to read intermediate cert file")

	if reflect.DeepEqual(intercert.Issuer, rootcert.Subject) && reflect.DeepEqual(intercert.Subject, intercert.Issuer) {
		t.Errorf("Not a valid intermediate certificate '%s' stored in '%s' directory", interCertPath, filepath.Base(interCertsDir))
	}
}

// TestThreeCAHierarchy runs testThreeCAHierarchy test with and without
// setting the environment variable CA_CHAIN_PARENT_FIRST
func TestThreeCAHierarchy(t *testing.T) {
	parentFirstEnvVal := os.Getenv(lib.CAChainParentFirstEnvVar)
	os.Unsetenv(lib.CAChainParentFirstEnvVar)
	defer os.Setenv(lib.CAChainParentFirstEnvVar, parentFirstEnvVal)
	testThreeCAHierarchy(t)

	os.Setenv(lib.CAChainParentFirstEnvVar, "true")
	testThreeCAHierarchy(t)
}

// testThreeCAHierarchy tests three CA hierarchy (root CA -- intermediate CA -- Issuing CA)
// The client enrolls a user with the Issuing CA and checks if the there is one root CA cert
// in the 'cacerts' folder of client msp and two intermediate CA certs in the pem file in
// the 'intermediatecerts' folder.
func testThreeCAHierarchy(t *testing.T) {
	validateCACerts := func(rootCertDir, interCertsDir string) {
		files, err := ioutil.ReadDir(rootCertDir)
		file := files[0].Name()
		rootCertPath := filepath.Join(rootCertDir, file)
		rootcaCertBytes, err := util.ReadFile(rootCertPath)
		assert.NoError(t, err, "Failed to read root CA certificate file %s", rootCertPath)
		rootcerts, err := util.GetX509CertificatesFromPEM(rootcaCertBytes)
		assert.NoError(t, err, "Failed to retrieve root certificate from root CA certificate file")
		assert.Equal(t, 1, len(rootcerts), "There should be only one root CA certificate")
		assert.True(t, reflect.DeepEqual(rootcerts[0].Subject, rootcerts[0].Issuer),
			"Not a valid root certificate '%s' stored in the '%s' directory",
			rootCertPath, filepath.Base(rootCertDir))

		interCertPath := filepath.Join(interCertsDir, file)
		intcaCertBytes, err := util.ReadFile(interCertPath)
		assert.NoError(t, err, "Failed to read intermediate CA certificates file %s", interCertPath)
		intcerts, err := util.GetX509CertificatesFromPEM(intcaCertBytes)
		assert.NoError(t, err, "Failed to retrieve certs from intermediate CA certificates file")
		assert.Equal(t, 2, len(intcerts), "There should be 2 intermediate CA certificates")
		if os.Getenv(lib.CAChainParentFirstEnvVar) != "" {
			// Assert that first int CA cert's issuer must be root CA's subject
			assert.True(t, bytes.Equal(intcerts[0].RawIssuer, rootcerts[0].RawSubject), "Intermediate CA's issuer should be root CA's subject")

			// Assert that second int CA cert's issuer must be first int CA's subject
			assert.True(t, bytes.Equal(intcerts[1].RawIssuer, intcerts[0].RawSubject), "Issuing CA's issuer should be intermediate CA's subject")

			// Assert that first int CA's cert expires before or on root CA cert's expiry
			assert.False(t, intcerts[0].NotAfter.After(rootcerts[0].NotAfter), "Intermediate CA certificate expires after root CA's certificate")

			// Assert that second int CA's cert expires before or on first int CA cert's expiry
			assert.False(t, intcerts[1].NotAfter.After(intcerts[0].NotAfter), "Issuing CA certificate expires after intermediate CA's certificate")
		} else {
			// Assert that first int CA cert's issuer must be second int CA's subject
			assert.True(t, bytes.Equal(intcerts[0].RawIssuer, intcerts[1].RawSubject), "Issuing CA's issuer should be intermediate CA's subject")
			// Assert that second int CA cert's issuer must be root CA's subject
			assert.True(t, bytes.Equal(intcerts[1].RawIssuer, rootcerts[0].RawSubject), "Intermediate CA's issuer should be root CA's subject")

			// Assert that first int CA's cert expires before or on second int CA cert's expiry
			assert.False(t, intcerts[0].NotAfter.After(intcerts[1].NotAfter), "Issuing CA certificate expires after intermediate CA's certificate")
			// Assert that second int CA's cert expires before or on root CA cert's expiry
			assert.False(t, intcerts[1].NotAfter.After(rootcerts[0].NotAfter), "Intermediate CA certificate expires after root CA's certificate")
		}
	}

	multiIntCATestDir := "multi-intca-test"
	os.RemoveAll(multiIntCATestDir)
	defer os.RemoveAll(multiIntCATestDir)

	// Create and start the Root CA server
	rootCAPort := 7173
	// Set root server cert expiry to 30 days and start the server
	rootServer := startServerWithCustomExpiry(path.Join(multiIntCATestDir, "rootServer"), rootCAPort, "720h", t)
	defer rootServer.Stop()

	// Create and start the Intermediate CA server
	rootCAURL := fmt.Sprintf("http://admin:adminpw@localhost:%d", rootCAPort)
	intCAPort := 7174
	intServer := startServer(path.Join(multiIntCATestDir, "intServer"), intCAPort, rootCAURL, t)
	defer intServer.Stop()

	// Stop the Intermediate CA server to register identity of the Issuing CA
	err := intServer.Stop()
	if err != nil {
		t.Fatal("Failed to stop intermediate CA server after registering identity for the Issuing CA server")
	}

	// Register an identity for Issuing CA with the Intermediate CA, this identity will be used by the Issuing
	// CA to get it's CA certificate
	intCA1Admin := "int-ca1-admin"
	err = intServer.RegisterBootstrapUser(intCA1Admin, "adminpw", "")
	if err != nil {
		t.Fatal("Failed to register identity for the Issuing CA server")
	}

	// Restart the Intermediate CA server
	err = intServer.Start()
	if err != nil {
		t.Fatal("Failed to start intermediate CA server after registering identity for the Issuing CA server")
	}

	// Create and start the Issuing CA server
	intCAURL := fmt.Sprintf("http://%s:adminpw@localhost:%d", intCA1Admin, intCAPort)
	intCA1Port := 7175
	intServer1 := startServer(path.Join(multiIntCATestDir, "intServer1"), intCA1Port, intCAURL, t)
	defer intServer1.Stop()

	// Enroll bootstrap admin of the Issuing CA
	homedir := path.Join(multiIntCATestDir, "client")
	mspdir := "msp" // relative to homedir
	err = RunMain([]string{
		cmdName, "enroll",
		"-u", fmt.Sprintf("http://admin:adminpw@localhost:%d", intCA1Port),
		"-c", path.Join(homedir, "config.yaml"),
		"-M", mspdir, "-d"})
	if err != nil {
		t.Fatalf("Client enroll -u failed: %s", err)
	}

	assertFilesInDir(path.Join(homedir, mspdir, "keystore"), 1, t)
	assertFilesInDir(path.Join(homedir, mspdir, "cacerts"), 1, t)
	assertFilesInDir(path.Join(homedir, mspdir, "intermediatecerts"), 1, t)
	validateCACerts(path.Join(homedir, mspdir, "cacerts"), path.Join(homedir, mspdir, "intermediatecerts"))
}

// TestReenroll tests fabric-ca-client reenroll
func testReenroll(t *testing.T) {
	t.Log("Testing Reenroll command")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "reenroll", "-u", serverURL, "--csr.hosts", "host1,host2"})
	if err != nil {
		t.Errorf("client reenroll --url -f failed: %s", err)
	}

	err = util.CheckHostsInCert(
		filepath.Join(filepath.Dir(defYaml), "msp", "signcerts", "cert.pem"),
		"host1",
		"host2",
	)
	if err != nil {
		t.Error(err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-u", serverURL,
		"--enrollment.hosts", "host1,host2", "Z"})
	if err == nil {
		t.Error("reenroll called with bogus argument, should have failed")
	}
	os.Remove(defYaml)
}

// testRegisterConfigFile tests fabric-ca-client register using the config file
func testRegisterConfigFile(t *testing.T) {
	t.Log("Testing Register command using config file")

	err := RunMain([]string{cmdName, "enroll", "-d", "-c",
		"../../../testdata/fabric-ca-client-config.yaml", "-u", enrollURL1})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-d", "-c",
		"../../../testdata/fabric-ca-client-config.yaml"})
	if err != nil {
		t.Errorf("client register failed using config file: %s", err)
	}
}

// testRegisterEnvVar tests fabric-ca-client register using environment variables
func testRegisterEnvVar(t *testing.T) {
	t.Log("Testing Register command using env variables")

	os.Setenv("FABRIC_CA_CLIENT_HOME", tdDir)
	os.Setenv("FABRIC_CA_CLIENT_ID_NAME", "testRegister2")
	os.Setenv("FABRIC_CA_CLIENT_ID_AFFILIATION", "hyperledger.org2")
	os.Setenv("FABRIC_CA_CLIENT_ID_TYPE", "client")
	defer func() {
		os.Unsetenv("FABRIC_CA_CLIENT_HOME")
		os.Unsetenv("FABRIC_CA_CLIENT_ID_NAME")
		os.Unsetenv("FABRIC_CA_CLIENT_ID_AFFILIATION")
		os.Unsetenv("FABRIC_CA_CLIENT_ID_TYPE")
	}()

	err := RunMain([]string{cmdName, "register"})
	if err != nil {
		t.Errorf("client register failed using environment variables: %s", err)
	}
}

// testRegisterCommandLine tests fabric-ca-client register using command line input
func testRegisterCommandLine(t *testing.T, srv *lib.Server) {
	t.Log("Testing Register using command line options")
	os.Setenv("FABRIC_CA_CLIENT_HOME", tdDir)
	defer os.Unsetenv("FABRIC_CA_CLIENT_HOME")

	fooName := "foo"
	fooVal := "a=b"
	roleName := "hf.Registrar.Roles"
	roleVal := "peer,user"
	attributes := fmt.Sprintf("%s=%s,bar=c,\"%s=%s\"", fooName, fooVal, roleName, roleVal)

	err := RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister3",
		"--id.affiliation", "hyperledger.org1", "--id.type", "client", "--id.attrs",
		attributes})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	sqliteDB, err := getSqliteDb(srv.CA.Config.DB.Datasource)
	assert.NoError(t, err)

	db := lib.NewDBAccessor(sqliteDB)
	user, err := db.GetUser("testRegister3", nil)
	assert.NoError(t, err)

	allAttrs, _ := user.GetAttributes(nil)
	val := attr.GetAttrValue(allAttrs, fooName)
	if val != fooVal {
		t.Errorf("Incorrect value returned for attribute '%s', expected '%s' got '%s'", fooName, fooVal, val)
	}
	val = attr.GetAttrValue(allAttrs, roleName)
	if val != roleVal {
		t.Errorf("Incorrect value returned for attribute '%s', expected '%s' got '%s'", roleName, roleVal, val)
	}

	err = RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister4",
		"--id.secret", "testRegister4", "--id.affiliation", "hyperledger.org2", "--id.type", "user"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	// Register an identity without identity type parameter (--id.type). It should succeed.
	// The identity type is set to default type "client"
	userName := "testRegister5"
	err = RunMain([]string{cmdName, "register", "-d", "--id.name", userName,
		"--id.secret", "testRegister5", "--id.affiliation", "hyperledger.org1"})
	assert.NoError(t, err, "Failed to register identity "+userName)
	user, err = db.GetUser(userName, nil)
	assert.NoError(t, err)
	assert.Equal(t, "client", user.GetType(), "Identity type for '%s' should have been 'user'", userName)

	// Register an identity with a space in its name
	userName = "Test Register5"
	err = RunMain([]string{cmdName, "register", "-d", "--id.name", userName,
		"--id.affiliation", "hyperledger.org1"})
	assert.NoError(t, err, "Failed to register identity "+userName)
	user, err = db.GetUser(userName, nil)
	assert.NoError(t, err)
	assert.Equal(t, "client", user.GetType(), "Identity type for '%s' should have been 'user'", userName)

	// Register an identity with no max enrollment specified should pick up CA's make enrollment
	srv.CA.Config.Registry.MaxEnrollments = 200

	userName = "Test Register6"
	err = RunMain([]string{cmdName, "register", "-d", "--id.name", userName,
		"--id.affiliation", "hyperledger.org1"})
	assert.NoError(t, err, "Failed to register identity "+userName)
	user, err = db.GetUser(userName, nil)
	assert.NoError(t, err)
	assert.Equal(t, "client", user.GetType(), "Identity type for '%s' should have been 'user'", userName)
	assert.Equal(t, 200, user.GetMaxEnrollments())

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "register", "-u", "http://localhost:7091"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7091) for server")
	}

	err = RunMain([]string{cmdName, "register", "-u", serverURL, "Y"})
	if err == nil {
		t.Error("register called with bogus argument, should have failed")
	}
}

// TestRevoke tests fabric-ca-client revoke
func testRevoke(t *testing.T) {
	t.Log("Testing Revoke command")
	clientHome := tdDir
	os.Setenv("FABRIC_CA_CLIENT_HOME", clientHome)
	defer os.Unsetenv("FABRIC_CA_CLIENT_HOME")

	err := RunMain([]string{cmdName, "revoke"})
	if err == nil {
		t.Errorf("No enrollment ID or serial/aki provided, should have failed")
	}

	serial, aki, err := getSerialAKIByID("admin")
	if err != nil {
		t.Error(err)
	}

	// Revoker's affiliation: hyperledger
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.name", "nonexistinguser"})
	if err == nil {
		t.Errorf("Non existing user being revoked, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.serial", serial})
	if err == nil {
		t.Errorf("Only serial specified, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.aki", aki})
	if err == nil {
		t.Errorf("Only aki specified, should have failed")
	}

	// revoker's affiliation: hyperledger, revoking affiliation: ""
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.serial", serial, "--revoke.aki", aki})
	if err == nil {
		t.Error("Should have failed, admin2 cannot revoke root affiliation")
	}

	// When serial, aki and enrollment id are specified in a revoke request,
	// fabric ca server returns an error if the serial and aki do not belong
	// to the enrollment ID.
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.name", "blah", "--revoke.serial", serial, "--revoke.aki", aki})
	if err == nil {
		t.Errorf("The Serial and AKI are not associated with the enrollment ID: %s", err)
	}

	// Enroll testRegister4
	testRegister4Home := filepath.Join(os.TempDir(), "testregister4Home")
	defer os.RemoveAll(testRegister4Home)
	err = RunMain([]string{cmdName, "enroll", "-u",
		fmt.Sprintf("http://testRegister4:testRegister4@localhost:%d", serverPort)})
	if err != nil {
		t.Fatalf("Failed to enroll testRegister4 user: %s", err)
	}

	// testRegister2's affiliation: hyperledger.org2, hyperledger.org2
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "--revoke.name",
		"testRegister2", "--revoke.serial", "", "--revoke.aki", ""})
	if err == nil {
		t.Errorf("Revoker has different type than the identity being revoked, should have failed")
	}

	// Enroll admin with root affiliation and test revoking with root
	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	if err != nil {
		t.Fatalf("client enroll -u failed: %s", err)
	}

	// testRegister4's affiliation: company2, revoker's affiliation: "" (root)
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "--revoke.name",
		"testRegister4", "--revoke.serial", "", "--revoke.aki", "", "--gencrl"})
	if err != nil {
		t.Errorf("User with root affiliation failed to revoke, error: %s", err)
	}

	crlFile := filepath.Join(clientHome, "msp/crls/crl.pem")
	_, err = os.Stat(crlFile)
	assert.NoError(t, err, "CRL should be created when revoke is called with --gencrl parameter")

	// Remove the CRL file created by revoke command
	err = os.Remove(crlFile)
	if err != nil {
		t.Fatalf("Failed to delete the CRL file '%s': %s", crlFile, err)
	}

	// Enroll testRegister5, so the next revoke command will revoke atleast one
	// ecert
	testRegister5Home := filepath.Join(os.TempDir(), "testregister5Home")
	defer os.RemoveAll(testRegister5Home)
	err = RunMain([]string{cmdName, "enroll", "-u",
		fmt.Sprintf("http://testRegister5:testRegister5@localhost:%d", serverPort), "-H", testRegister5Home})
	if err != nil {
		t.Fatalf("Failed to enroll testRegister5 user: %s", err)
	}

	testRegister5Serial, testRegister5AKI, err := getSerialAKIByID("testRegister5")
	if err != nil {
		t.Fatalf("Failed to get serial and aki of the enrollment certificate of the user 'testRegister5': %s", err)
	}

	// Revoke testRegister5 without --gencrl option, so it does not create a CRL
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "--revoke.name",
		"testRegister5", "--revoke.serial", "", "--revoke.aki", ""})
	if err != nil {
		t.Errorf("Failed to revoke testRegister5, error: %s", err)
	}
	_, err = os.Stat(filepath.Join(clientHome, "msp/crls/crl.pem"))
	assert.Error(t, err, "CRL should not be created when revoke is called without --gencrl parameter")

	// Revoke testRegister5 certificate that was revoked by the above revoke command, we expect
	// an error in this case
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL,
		"--revoke.serial", testRegister5Serial, "--revoke.aki", testRegister5AKI})
	if err == nil {
		t.Error("Revoke of testRegister5's certificate should have failed as it was already revoked")
	}

	err = RunMain([]string{cmdName, "enroll", "-d", "-u", "http://admin3:adminpw3@localhost:7090"})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	// Revoked user's affiliation: hyperledger.org3
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "--revoke.name",
		"testRegister3", "--revoke.serial", "", "--revoke.aki", ""})
	if err == nil {
		t.Error("Should have failed, admin3 does not have authority revoke")
	}

	// testRegister4's affiliation: company2, revoker's affiliation: company1
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "--revoke.name",
		"testRegister4"})
	if err == nil {
		t.Error("Should have failed have different affiliation path")
	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7091"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7091) for server")
	}
	err = RunMain([]string{cmdName, "revoke", "-u", serverURL, "U"})
	if err == nil {
		t.Error("revoke called with bogus argument, should have failed")
	}

	os.RemoveAll(filepath.Dir(defYaml))
}

// Test that affiliations get correctly set when registering a user with affiliation specified
func testAffiliation(t *testing.T) {
	var err error

	// admin2 has affiliation of 'hyperledger'
	err = RunMain([]string{cmdName, "enroll", "-d", "-u", enrollURL1})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	// Registering with affiliation of "", should result in error. Registrar does not have absolute root affiliaton
	err = RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister5", "--id.type", "client", "--id.affiliation", "."})
	if err == nil {
		t.Error("Registering with affiliation of '', should result in error. Registrar does not have absolute root affiliaton")
	}

	// admin has affiliation of ""
	err = RunMain([]string{cmdName, "enroll", "-d", "-u", enrollURL})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	// Registering with affiliation of "hyperledger", valid scenario
	err = RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister6", "--id.type", "client", "--id.affiliation", "hyperledger"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	sqliteDB, err := getSqliteDb(srv.CA.Config.DB.Datasource)
	assert.NoError(t, err)

	db := lib.NewDBAccessor(sqliteDB)
	user, err := db.GetUser("testRegister6", nil)
	assert.NoError(t, err)

	userAff := cadbuser.GetAffiliation(user)
	if userAff != "hyperledger" {
		t.Errorf("Incorrectly set affiliation for user being registered when no affiliation was specified, expected 'hyperledger' got %s", userAff)
	}

	os.RemoveAll(filepath.Dir(defYaml))
}

// testProfiling tests enablement of fabric CA client heap/cpu profiling
func testProfiling(t *testing.T) {
	t.Log("Testing profiling")
	var testCases = []struct {
		pEnvVal       string
		input         []string
		mProfExpected bool
		cProfExpected bool
	}{
		{"heap", []string{cmdName, "getcacert", "-u", serverURL}, true, false},
		{"cpu", []string{cmdName, "getcacert", "-u", serverURL}, false, true},
		{"", []string{cmdName, "getcacert", "-u", serverURL}, false, false},
		{"foo", []string{cmdName, "getcacert", "-u", serverURL}, false, false},
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = os.Getenv("HOME")
	}
	mfile := wd + "/mem.pprof"
	cfile := wd + "/cpu.pprof"
	for _, testCase := range testCases {
		os.Setenv(fabricCAClientProfileMode, testCase.pEnvVal)
		_ = RunMain(testCase.input)
		_, err := os.Stat(mfile)
		_, err1 := os.Stat(cfile)
		if testCase.cProfExpected && err1 != nil {
			t.Errorf("%s is found. It should not be created when cpu profiling is NOT enabled: %s", cfile, err1)
		}
		if !testCase.cProfExpected && err1 == nil {
			t.Errorf("%s is not found. It should be created when cpu profiling is enabled", cfile)
		}
		if testCase.mProfExpected && err != nil {
			t.Errorf("%s is found. It should not be created when memory profiling is NOT enabled: %s", mfile, err)
		}
		if !testCase.mProfExpected && err == nil {
			t.Errorf("%s is not found. It should be created when memory profiling is enabled", mfile)
		}
		os.Remove(mfile)
		os.Remove(cfile)
		os.Remove(defYaml)
	}
	os.Unsetenv(fabricCAClientProfileMode)
}

// TestBogus tests a negative test case
func testBogus(t *testing.T) {
	err := RunMain([]string{cmdName, "bogus"})
	if err == nil {
		t.Errorf("client bogus passed but should have failed")
	}
}

func TestGetCACert(t *testing.T) {
	srv = getServer()
	srv.Config.Debug = true

	// Configure TLS settings on server
	srv.HomeDir = tdDir
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = tlsCertFile
	srv.Config.TLS.KeyFile = tlsKeyFile

	err := srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	// Test getcacert command using environment variables to set root TLS cert
	err = testGetCACertEnvVar(t)
	assert.NoError(t, err, "Failed to get CA cert using environment variables")

	// Change client authentication type on server
	srv.Config.TLS.ClientAuth.Type = "RequireAndVerifyClientCert"

	// Test getcacert command using configuration files to read in client TLS cert and key
	err = testGetCACertConfigFile(t)
	assert.NoError(t, err, "Failed to get CA cert using client configuration file")

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestClientCommandsUsingConfigFile(t *testing.T) {
	os.Remove(fabricCADB)

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "org1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.HomeDir = tdDir
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = tlsCertFile
	srv.Config.TLS.KeyFile = tlsKeyFile

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c",
		filepath.Join(tdDir, "fabric-ca-client-config.yaml"), "-u",
		tlsEnrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestClientCommandsTLSEnvVar(t *testing.T) {
	os.Remove(fabricCADB)

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin2", "adminpw2", "org1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.HomeDir = tdDir
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = tlsCertFile
	srv.Config.TLS.KeyFile = tlsKeyFile

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	os.Setenv(rootCertEnvVar, rootCert)
	os.Setenv(clientKeyEnvVar, tlsClientKeyFile)
	os.Setenv(clientCertEnvVar, tlsClientCertFile)

	err = RunMain([]string{cmdName, "enroll", "-d", "-c", testYaml,
		"-u", tlsEnrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

	os.Unsetenv(rootCertEnvVar)
	os.Unsetenv(clientKeyEnvVar)
	os.Unsetenv(clientCertEnvVar)
}

func TestClientCommandsTLS(t *testing.T) {
	os.Remove(fabricCADB)

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin2", "adminpw2", "org1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.HomeDir = tdDir
	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = tlsCertFile
	srv.Config.TLS.KeyFile = tlsKeyFile

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "--tls.certfiles",
		rootCert, "--tls.client.keyfile", tlsClientKeyFile, "--tls.client.certfile",
		tlsClientCertFile, "-u", tlsEnrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "--tls.certfiles",
		rootCert, "--tls.client.keyfile", tlsClientKeyFile, "--tls.client.certfile",
		tlsClientCertExpired, "-u", tlsEnrollURL, "-d"})
	if err == nil {
		t.Errorf("Expired certificate used for TLS connection, should have failed")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
	os.Remove(testYaml)
}

func TestMultiCA(t *testing.T) {
	cleanMultiCADir()

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	srv.HomeDir = tdDir
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml",
		"ca/rootca/ca2/fabric-ca-server-config.yaml"}
	srv.CA.Config.CSR.Hosts = []string{"hostname"}
	t.Logf("Server configuration: %+v\n", srv.Config)

	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	srv.BlockingStart = false
	err = srv.Start()
	if err != nil {
		t.Fatal("Failed to start server:", err)
	}

	// Test going to default CA if no caname provided in client request
	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", enrollURL, "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	enrURL := fmt.Sprintf("http://adminca1:adminca1pw@localhost:%d", serverPort)
	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", enrURL, "-d",
		"--caname", "rootca1"})
	if err != nil {
		t.Errorf("client enroll -c -u --caname failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-c", testYaml, "-d", "--caname",
		"rootca1"})
	if err != nil {
		t.Errorf("client reenroll -c --caname failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-c", testYaml, "-d", "--id.name",
		"testuser", "--id.type", "user", "--id.affiliation", "org2", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	err = RunMain([]string{cmdName, "revoke", "-c", testYaml, "-d",
		"--revoke.name", "adminca1", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client revoke failed: %s", err)
	}

	err = RunMain([]string{cmdName, "getcacert", "-u", serverURL, "-c", testYaml, "-d",
		"--caname", "rootca1"})
	if err != nil {
		t.Errorf("client getcacert failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u",
		enrollURL, "-d", "--caname", "rootca2"})
	if err != nil {
		t.Errorf("client enroll failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u",
		enrURL, "-d", "--caname", "rootca3"})
	if err == nil {
		t.Errorf("Should have failed, rootca3 does not exist on server")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestMSPDirectoryCreation(t *testing.T) {
	os.RemoveAll("mspConfigTest")
	defer os.RemoveAll("mspConfigTest")
	srv := lib.TestGetServer(serverPort, "mspConfigTest", "", -1, t)

	err := srv.Start()
	if err != nil {
		t.Fatal("Failed to start server:", err)
	}

	if util.FileExists("msp") {
		t.Errorf("MSP directory should not exist at the local directory")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestHomeDirectory(t *testing.T) {
	configFilePath := util.GetDefaultConfigFile(clientCMD)
	defaultClientConfigDir, defaultClientConfigFile := filepath.Split(configFilePath)

	dir := filepath.Join(tdDir, "testhome")
	os.RemoveAll(dir)
	defer os.RemoveAll(dir)

	RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-c", ""})
	if !util.FileExists(configFilePath) {
		t.Errorf("Failed to correctly created the default config (fabric-ca-client-config) in the default home directory")
	}

	os.RemoveAll(defaultClientConfigDir) // Remove default directory before testing another default case

	RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-H", ""})
	if !util.FileExists(configFilePath) {
		t.Errorf("Failed to correctly created the default config (fabric-ca-client-config) in the default home directory")
	}

	os.RemoveAll(defaultClientConfigDir) // Remove default directory before testing another default case

	RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	if !util.FileExists(configFilePath) {
		t.Errorf("Failed to correctly created the default config (fabric-ca-client-config) in the default home directory")
	}

	RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-H", filepath.Join(tdDir, "testhome/testclientcmd")})
	if !util.FileExists(filepath.Join(tdDir, "testhome/testclientcmd", defaultClientConfigFile)) {
		t.Errorf("Failed to correctly created the default config (fabric-ca-client-config.yaml) in the '../../../testdata/testhome/testclientcmd' directory")
	}

	RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-d", "-c", filepath.Join(tdDir, "testhome/testclientcmd2/testconfig2.yaml")})
	if !util.FileExists(filepath.Join(tdDir, "testhome/testclientcmd2/testconfig2.yaml")) {
		t.Errorf("Failed to correctly created the config (testconfig2.yaml) in the '../../../testdata/testhome/testclientcmd2' directory")
	}

	RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-d", "-H", filepath.Join(tdDir, "testclientcmd3"), "-c", filepath.Join(tdDir, "testhome/testclientcmd3/testconfig3.yaml")})
	if !util.FileExists(filepath.Join(tdDir, "testhome/testclientcmd3/testconfig3.yaml")) {
		t.Errorf("Failed to correctly created the config (testconfig3.yaml) in the '../../../testdata/testhome/testclientcmd3' directory")
	}

}

func TestDebugSetting(t *testing.T) {
	os.RemoveAll(testdataDir)
	defer os.RemoveAll(testdataDir)

	srv = lib.TestGetServer(serverPort, testdataDir, "", -1, t)
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL})
	util.FatalError(t, err, "Failed to enroll user")

	err = RunMain([]string{cmdName, "affiliation", "list"})
	assert.NoError(t, err, "Failed to return all affiliations")
	assert.Equal(t, 2, log.Level) // Default level for listing affiliations is warning (2)

	err = RunMain([]string{cmdName, "affiliation", "list", "-d"})
	assert.NoError(t, err, "Failed to return all affiliations")
	assert.Equal(t, 0, log.Level) // With '-d' flag log level should be debug (0)

	err = RunMain([]string{cmdName, "identity", "list"})
	assert.NoError(t, err, "Failed to return all affiliations")
	assert.Equal(t, 2, log.Level) // Default level for listing identities is warning (2)

	err = RunMain([]string{cmdName, "identity", "list", "-d"})
	assert.NoError(t, err, "Failed to return all affiliations")
	assert.Equal(t, 0, log.Level) // With '-d' flag log level should be debug (0)
}

func TestClientLogLevelCLI(t *testing.T) {
	// Not passing in -u flag, don't need for the enroll to complete successfully to
	// verify that the log level is correctly getting set
	RunMain([]string{cmdName, "enroll", "--loglevel", "info"})
	assert.Equal(t, log.Level, log.LevelInfo)

	RunMain([]string{cmdName, "enroll", "--loglevel", "debug"})
	assert.Equal(t, log.Level, log.LevelDebug)

	RunMain([]string{cmdName, "enroll", "--loglevel", "warning"})
	assert.Equal(t, log.Level, log.LevelWarning)

	RunMain([]string{cmdName, "enroll", "--loglevel", "fatal"})
	assert.Equal(t, log.Level, log.LevelFatal)

	RunMain([]string{cmdName, "enroll", "--loglevel", "critical"})
	assert.Equal(t, log.Level, log.LevelCritical)
}

func TestClientLogLevelEnvVar(t *testing.T) {
	// Not passing in -u flag, don't need for the enroll to complete successfully to
	// verify that the log level is correctly getting set
	os.Setenv("FABRIC_CA_CLIENT_LOGLEVEL", "info")
	RunMain([]string{cmdName, "enroll"})
	assert.Equal(t, log.Level, log.LevelInfo)

	os.Setenv("FABRIC_CA_CLIENT_LOGLEVEL", "debug")
	RunMain([]string{cmdName, "enroll"})
	assert.Equal(t, log.Level, log.LevelDebug)

	os.Setenv("FABRIC_CA_CLIENT_LOGLEVEL", "warning")
	RunMain([]string{cmdName, "enroll"})
	assert.Equal(t, log.Level, log.LevelWarning)

	os.Setenv("FABRIC_CA_CLIENT_LOGLEVEL", "fatal")
	RunMain([]string{cmdName, "enroll"})
	assert.Equal(t, log.Level, log.LevelFatal)

	os.Setenv("FABRIC_CA_CLIENT_LOGLEVEL", "critical")
	RunMain([]string{cmdName, "enroll"})
	assert.Equal(t, log.Level, log.LevelCritical)
}

func TestCleanUp(t *testing.T) {
	os.Remove(filepath.Join(tdDir, "ca-cert.pem"))
	os.Remove(filepath.Join(tdDir, "ca-key.pem"))
	os.Remove(filepath.Join(tdDir, "IssuerPublicKey"))
	os.Remove(filepath.Join(tdDir, "IssuerSecretKey"))
	os.Remove(filepath.Join(tdDir, "IssuerRevocationPublicKey"))
	os.Remove(testYaml)
	os.Remove(fabricCADB)
	os.RemoveAll(mspDir)
	os.RemoveAll(moptionDir)
	cleanMultiCADir()
}

func cleanMultiCADir() {
	caFolder := filepath.Join(tdDir, "ca/rootca")
	nestedFolders := []string{"ca1", "ca2"}
	removeFiles := []string{"msp", "ca-cert.pem",
		"fabric-ca-server.db", "fabric-ca2-server.db", "ca-chain.pem", "IssuerPublicKey", "IssuerSecretKey", "IssuerRevocationPublicKey"}

	for _, nestedFolder := range nestedFolders {
		path := filepath.Join(caFolder, nestedFolder)
		for _, file := range removeFiles {
			os.RemoveAll(filepath.Join(path, file))
		}
		os.RemoveAll(filepath.Join(path, "msp"))
	}
}

func TestRegisterWithoutEnroll(t *testing.T) {
	err := RunMain([]string{cmdName, "register", "-c", testYaml})
	if err == nil {
		t.Errorf("Should have failed, as no enrollment information should exist. Enroll commands needs to be the first command to be executed")
	}
}

func testGetCACertEnvVar(t *testing.T) error {
	t.Log("testGetCACertEnvVar - Entered")
	os.Setenv(rootCertEnvVar, filepath.Join(tdDir, "root.pem"))
	defer os.Unsetenv(rootCertEnvVar)

	defer os.RemoveAll("msp")
	err := RunMain([]string{cmdName, "getcacert", "-d", "-c", "fakeConfig.yaml", "-u", tlsServerURL,
		"--tls.client.certfile", "", "--tls.client.keyfile", "", "--caname", ""})
	if err != nil {
		return fmt.Errorf("getcainfo failed: %s", err)
	}

	return nil
}

func testGetCACertConfigFile(t *testing.T) error {
	t.Log("testGetCACertConfigFile - Entered")
	configFile := filepath.Join(tdDir, "fabric-ca-client-config.yaml")

	err := RunMain([]string{cmdName, "getcacert", "-d", "-c", configFile, "-u", tlsServerURL, "--tls.certfiles", rootCert})
	if err != nil {
		return fmt.Errorf("getcainfo failed: %s", err)
	}

	return nil
}

func TestVersion(t *testing.T) {
	err := RunMain([]string{cmdName, "version"})
	if err != nil {
		t.Error("Failed to get fabric-ca-client version: ", err)
	}
}

func captureOutput(f func(args []string) error, args []string) (string, error) {
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

func getServer() *lib.Server {
	return &lib.Server{
		HomeDir: ".",
		Config:  getServerConfig(),
		CA: lib.CA{
			Config: getCAConfig(),
		},
	}
}

func getServerConfig() *lib.ServerConfig {
	return &lib.ServerConfig{
		Debug: true,
		Port:  serverPort,
	}
}

func getCAConfig() *lib.CAConfig {
	affiliations := map[string]interface{}{
		"org1": nil,
	}

	return &lib.CAConfig{
		CA: lib.CAInfo{
			Keyfile:  keyfile,
			Certfile: certfile,
		},
		Affiliations: affiliations,
		CSR: api.CSRInfo{
			CN: "TestCN",
		},
	}
}

func setupIdentityCmdTest(t *testing.T, id lib.CAConfigIdentity) *lib.Server {
	srvHome := filepath.Join(tdDir, "identityCmdTestHome")
	err := os.RemoveAll(srvHome)
	if err != nil {
		t.Fatalf("Failed to remove home directory %s: %s", srvHome, err)
	}
	affiliations := map[string]interface{}{"org1": nil}
	srv := &lib.Server{
		HomeDir: srvHome,
		Config: &lib.ServerConfig{
			Debug: true,
			Port:  serverPort,
		},
		CA: lib.CA{
			Config: &lib.CAConfig{
				Affiliations: affiliations,
				Registry: lib.CAConfigRegistry{
					MaxEnrollments: -1,
				},
			},
		},
	}
	srv.CA.Config.Registry.Identities = append(srv.CA.Config.Registry.Identities, id)

	err = srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Fatalf("Failed to register bootstrap user: %s", err)
	}
	err = srv.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}
	return srv
}

func getUser(id string, server *lib.Server) (cadbuser.User, error) {
	testdb, err := getSqliteDb(server.CA.Config.DB.Datasource)
	if err != nil {
		return nil, err
	}
	db := lib.NewDBAccessor(testdb)
	return db.GetUser(id, nil)
}

func getSerialAKIByID(id string) (serial, aki string, err error) {
	testdb, err := getSqliteDb(srv.CA.Config.DB.Datasource)
	if err != nil {
		return "", "", err
	}
	acc := lib.NewCertDBAccessor(testdb, 0)

	certs, err := acc.GetCertificatesByID(id)
	if err != nil {
		return "", "", err
	}

	block, _ := pem.Decode([]byte(certs[0].PEM))
	if block == nil {
		return "", "", errors.New("Failed to PEM decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("Error from x509.ParseCertificate: %s", err)
	}

	serial = util.GetSerialAsHex(x509Cert.SerialNumber)
	aki = hex.EncodeToString(x509Cert.AuthorityKeyId)

	return
}

func getSqliteDb(datasource string) (*db.DB, error) {
	sqliteDB := sqlite.NewDB(datasource, "", nil)
	err := sqliteDB.Connect()
	if err != nil {
		return nil, err
	}
	testdb, err := sqliteDB.Create()
	if err != nil {
		return nil, err
	}
	return testdb, nil
}

func setupEnrollTest(t *testing.T) *lib.Server {
	srvHome := filepath.Join(tdDir, "enrollsrvhome")
	err := os.RemoveAll(srvHome)
	if err != nil {
		t.Fatalf("Failed to remove home directory %s: %s", srvHome, err)
	}
	srv = lib.TestGetServer(serverPort, srvHome, "", -1, t)
	srv.Config.Debug = true

	err = srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "hyperledger")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	aff := make(map[string]interface{})
	aff["hyperledger"] = []string{"org1", "org2", "org3"}
	aff["company1"] = []string{"dept1"}
	aff["company2"] = []string{}

	srv.CA.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}
	return srv
}

func setupGenCRLTest(t *testing.T, adminHome string) *lib.Server {
	srvHome := filepath.Join(tdDir, "gencrlsrvhom")
	err := os.RemoveAll(srvHome)
	if err != nil {
		t.Fatalf("Failed to remove home directory %s: %s", srvHome, err)
	}

	srv := lib.TestGetServer(serverPort, srvHome, "", -1, t)
	srv.Config.Debug = true
	srv.CA.Config.CRL.Expiry = crlExpiry
	d, _ := time.ParseDuration("2h")
	srv.CA.Config.Signing.Default.Expiry = d

	adminName := "admin"
	adminPass := "adminpw"
	err = srv.RegisterBootstrapUser(adminName, adminPass, "")
	if err != nil {
		t.Fatalf("Failed to register bootstrap user: %s", err)
	}

	err = srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-H", adminHome})
	if err != nil {
		t.Fatalf("Failed to enroll admin: %s", err)
	}
	return srv
}

func stopAndCleanupServer(t *testing.T, srv *lib.Server) {
	if srv != nil {
		defer os.RemoveAll(srv.HomeDir)
		err := srv.Stop()
		if err != nil {
			t.Errorf("Server stop failed: %s", err)
		}
	}
}

// Checks if the generated CRL is in PEM format and contains expected
// revoked certificates
func checkCRL(t *testing.T, client *lib.Client, revokedSerials []*big.Int) {
	crlfile := filepath.Join(client.Config.MSPDir, "crls/crl.pem")
	crl, err := ioutil.ReadFile(crlfile)
	assert.NoError(t, err, "Failed to read the CRL from the file %s", crlfile)
	blk, _ := pem.Decode(crl)
	assert.Equal(t, blk.Type, "X509 CRL", "The %s is not a pem encoded CRL")

	revokedList, err := x509.ParseCRL(crl)
	assert.False(t, revokedList.HasExpired(time.Now().UTC().Add(crlExpiry-time.Hour)), "Next Update value is not set to expected value (240h)")
	assert.True(t, revokedList.HasExpired(time.Now().UTC().Add(crlExpiry+time.Hour)), "Next Update value is not set to expected value (240h)")
	assert.NoError(t, err, "Failed to parse the CRL")
	assert.Equal(t, len(revokedSerials), len(revokedList.TBSCertList.RevokedCertificates),
		"CRL contains unexpected number of revoked certificates")
	t.Logf("Revoked certs from the CRL: %v", revokedList.TBSCertList.RevokedCertificates)
	for _, revokedCert := range revokedList.TBSCertList.RevokedCertificates {
		serial := util.GetSerialAsHex(revokedCert.SerialNumber)
		found := false
		for _, revokedSerial := range revokedSerials {
			if revokedCert.SerialNumber.Cmp(revokedSerial) == 0 {
				found = true
				break
			}
		}
		assert.True(t, found, "Certificate %s is not one of revoked certificates", serial)
	}
}

// Registers, enrolls and revokes specified number of users. This is
// a utility function used by the gencrl test cases
func registerAndRevokeUsers(t *testing.T, admin *lib.Identity, num int) []*big.Int {
	var serials []*big.Int
	for i := 0; i < num; i++ {
		userName := "gencrluser" + strconv.Itoa(i)
		// Register a user
		regRes, err := admin.Register(&api.RegistrationRequest{
			Name:        userName,
			Type:        "user",
			Affiliation: "org2",
		})
		if err != nil {
			t.Fatalf("Failed to register the identity '%s': %s", userName, err)
		}

		// Enroll the user
		enrollResp, err := admin.GetClient().Enroll(&api.EnrollmentRequest{
			Name:   userName,
			Secret: regRes.Secret,
			CSR:    &api.CSRInfo{Hosts: []string{"localhost"}},
		})
		if err != nil {
			t.Fatalf("Failed to enroll the identity '%s': %s", userName, err)
		}

		x509Cred := enrollResp.Identity.GetECert()
		if x509Cred == nil || x509Cred.GetX509Cert() == nil {
			t.Fatalf("Failed to get enrollment certificate for the user %s", userName)
		}
		cert := x509Cred.GetX509Cert()
		revokeReq := &api.RevocationRequest{}
		if i%2 == 0 {
			revokeReq.Name = userName
		} else {
			revokeReq.Serial = util.GetSerialAsHex(cert.SerialNumber)
			revokeReq.AKI = hex.EncodeToString(cert.AuthorityKeyId)
			// Reenroll the user, this should create a new certificate, so this
			// user will have two valid certificates, but we will revoke one
			// of her certificate only
			_, err := enrollResp.Identity.Reenroll(&api.ReenrollmentRequest{})
			if err != nil {
				t.Fatalf("Reenrollment of user %s failed: %s", userName, err)
			}
		}

		// Revoke the user cert
		_, err = admin.Revoke(revokeReq)
		if err != nil {
			t.Fatalf("Failed to revoke the identity '%s': %s", userName, err)
		}

		serials = append(serials, cert.SerialNumber)
	}
	t.Logf("Revoked certificates: %v", serials)
	return serials
}

func setupGenCSRTest(t *testing.T, adminHome string) *lib.Server {
	srvHome := filepath.Join(tdDir, "gencsrsrvhome")
	err := os.RemoveAll(srvHome)
	if err != nil {
		t.Fatalf("Failed to remove home directory %s: %s", srvHome, err)
	}

	srv := lib.TestGetServer(serverPort, srvHome, "", -1, t)
	srv.Config.Debug = true
	srv.CA.Config.CSR.KeyRequest = &api.BasicKeyRequest{Algo: "ecdsa", Size: 384}

	adminName := "admin"
	adminPass := "adminpw"
	err = srv.RegisterBootstrapUser(adminName, adminPass, "")
	if err != nil {
		t.Fatalf("Failed to register bootstrap user: %s", err)
	}

	err = srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-H", adminHome})
	if err != nil {
		t.Fatalf("Failed to enroll admin: %s", err)
	}
	return srv
}

func extraArgErrorTest(in *TestData, t *testing.T) {
	err := RunMain(in.input)
	if err == nil {
		assert.Error(t, errors.New("Should have resulted in an error as extra agruments provided"))
	}
	if err != nil {
		assert.Contains(t, err.Error(), "Unrecognized arguments found",
			"Failed for other reason besides unrecognized argument")
	}
}

// Make sure there is exactly one file in a directory
func assertFilesInDir(dir string, numFiles int, t *testing.T) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatalf("Failed to get number of files in directory '%s': %s", dir, err)
	}
	count := len(files)
	if count != numFiles {
		t.Fatalf("Expecting %d file in %s but found %d", numFiles, dir, count)
	}
}

func startServer(home string, port int, parentURL string, t *testing.T) *lib.Server {
	affiliations := map[string]interface{}{"org1": nil}
	srv := &lib.Server{
		HomeDir: home,
		Config: &lib.ServerConfig{
			Debug: true,
			Port:  port,
		},
		CA: lib.CA{
			Config: &lib.CAConfig{
				Affiliations: affiliations,
				Registry: lib.CAConfigRegistry{
					MaxEnrollments: -1,
				},
			},
		},
	}
	if parentURL != "" {
		srv.CA.Config.Intermediate.ParentServer.URL = parentURL
	}
	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Fatalf("Failed to register bootstrap user: %s", err)
	}
	err = srv.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}
	return srv
}

func getAttrsMap(attrs []api.Attribute) map[string]api.Attribute {
	attrMap := make(map[string]api.Attribute)
	for _, attr := range attrs {
		attrMap[attr.Name] = api.Attribute{
			Name:  attr.Name,
			Value: attr.Value,
			ECert: attr.ECert,
		}
	}
	return attrMap
}

func startServerWithCustomExpiry(home string, port int, certExpiry string, t *testing.T) *lib.Server {
	affiliations := map[string]interface{}{"org1": nil}
	srv := &lib.Server{
		HomeDir: home,
		Config: &lib.ServerConfig{
			Debug: true,
			Port:  port,
		},
		CA: lib.CA{
			Config: &lib.CAConfig{
				Affiliations: affiliations,
				Registry: lib.CAConfigRegistry{
					MaxEnrollments: -1,
				},
				CSR: api.CSRInfo{
					CA: &csr.CAConfig{
						Expiry: certExpiry,
					},
				},
			},
		},
	}
	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Fatalf("Failed to register bootstrap user: %s", err)
	}
	err = srv.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}
	return srv
}
