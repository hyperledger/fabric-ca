/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const (
	initYaml    = "i.yaml"
	startYaml   = "s.yaml"
	ldapTestDir = "ldapTestDir"
)

var (
	longUserName = util.RandomString(1025)
)

var (
	longFileName = util.RandomString(261)
)

// Create a config element in unexpected format
var badSyntaxYaml = "bad.yaml"

// Unsupported file type
var unsupportedFileType = "config.txt"

type TestData struct {
	input    []string // input
	expected string   // expected result
}

// checkTest validates success cases
func checkTest(in *TestData, t *testing.T) {
	os.Args = in.input
	scmd := NewCommand(in.input[1], blockingStart)
	// Execute the command
	err := scmd.Execute()
	if err != nil {
		t.Errorf("FAILED:\n \tin: %v;\n \tout: %v\n \texpected: SUCCESS\n", in.input, err.Error())
	} else {
		signingProfile := scmd.cfg.CAcfg.Signing.Default
		ku, eku, unk := signingProfile.Usages()
		// expected key usage is digital signature
		assert.Equal(t, x509.KeyUsageDigitalSignature, ku, "Expected KeyUsageDigitalSignature")
		assert.Equal(t, 0, len(eku), "Found %d extended usages but expected 0", len(eku))
		assert.Equal(t, 0, len(unk), "Found %d unknown key usages", len(unk))
	}
}

// errorTest validates error cases
func errorTest(in *TestData, t *testing.T) {
	err := RunMain(in.input)
	if err != nil {
		matched, _ := regexp.MatchString(in.expected, err.Error())
		if !matched {
			t.Errorf("FAILED:\n \tin: %v;\n \tout: %v;\n \texpected: %v\n", in.input, err.Error(), in.expected)
		}
	} else {
		t.Errorf("FAILED:\n \tin: %v;\n \tout: <nil>\n \texpected: %v\n", in.input, in.expected)
	}
}

func TestMain(m *testing.M) {
	os.Setenv("FABRIC_CA_SERVER_OPERATIONS_LISTENADDRESS", "localhost:0")
	defer os.Unsetenv("FABRIC_CA_SERVER_OPERATIONS_LISTENADDRESS")

	metadata.Version = "1.1.0"
	os.Exit(m.Run())
}

func TestNoArguments(t *testing.T) {
	err := RunMain([]string{cmdName})
	if err == nil {
		assert.Error(t, errors.New("Should have resulted in an error as no agruments provided"))
	}
}

func TestErrors(t *testing.T) {
	os.Unsetenv(homeEnvVar)
	_ = ioutil.WriteFile(badSyntaxYaml, []byte("signing: true\n"), 0644)

	errorCases := []TestData{
		{[]string{cmdName, "init", "-c", initYaml}, "option is required"},
		{[]string{cmdName, "init", "-c", initYaml, "-n", "acme.com", "-b", "user::"}, "Failed to read"},
		{[]string{cmdName, "init", "-b", "user:pass", "-n", "acme.com", "ca.key"}, "Unrecognized arguments found"},
		{[]string{cmdName, "init", "-c", badSyntaxYaml, "-b", "user:pass"}, "Incorrect format"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", fmt.Sprintf("%s:foo", longUserName)}, "than 1024 characters"},
		{[]string{cmdName, "init", "-c", fmt.Sprintf("/tmp/%s.yaml", longFileName), "-b", "user:pass"}, "file name too long"},
		{[]string{cmdName, "init", "-b", "user:pass", "-c", unsupportedFileType}, "Unsupported Config Type"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", "user"}, "missing a colon"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", "user:"}, "empty password"},
		{[]string{cmdName, "bogus", "-c", initYaml, "-b", "user:pass"}, "unknown command"},
		{[]string{cmdName, "start", "-c"}, "needs an argument:"},
		{[]string{cmdName, "start", "--csr.keyrequest.algo", "fakeAlgo"}, "Invalid algorithm: fakeAlgo"},
		{[]string{cmdName, "start", "--csr.keyrequest.algo", "ecdsa", "--csr.keyrequest.size", "12345"}, "Invalid ECDSA key size: 12345"},
		{[]string{cmdName, "start", "-c", startYaml, "-b", "user:pass", "ca.key"}, "Unrecognized arguments found"},
	}

	for _, e := range errorCases {
		errorTest(&e, t)
		_ = os.Remove(initYaml)
	}
}

func TestOneTimePass(t *testing.T) {
	testDir := "oneTimePass"
	os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)
	// Test with "-b" option
	err := RunMain([]string{cmdName, "init", "-b", "admin:adminpw", "--registry.maxenrollments", "1", "-H", testDir})
	if err != nil {
		t.Fatalf("Failed to init server with one time passwords: %s", err)
	}
}

func TestLDAP(t *testing.T) {
	os.RemoveAll(ldapTestDir)
	defer os.RemoveAll(ldapTestDir)
	// Test with "-b" option
	err := RunMain([]string{cmdName, "init", "-c", path.Join(ldapTestDir, "config.yaml"),
		"-b", "a:b", "--ldap.enabled", "--ldap.url", "ldap://CN=admin@localhost:389/dc=example,dc=com"})
	if err != nil {
		t.Errorf("Failed to init server with LDAP enabled and -b: %s", err)
	}
	// Try without "-b" option
	os.RemoveAll(ldapTestDir)
	err = RunMain([]string{cmdName, "init", "-c", path.Join(ldapTestDir, "config.yaml"),
		"--ldap.enabled", "--ldap.url", "ldap://CN=admin@localhost:389/dc=example,dc=com"})
	if err != nil {
		t.Errorf("Failed to init server with LDAP enabled and no -b: %s", err)
	}
}

func TestValid(t *testing.T) {
	os.Unsetenv(homeEnvVar)
	blockingStart = false

	os.Setenv("CA_CFG_PATH", ".")
	validCases := []TestData{
		{[]string{cmdName, "init", "-b", "admin:a:d:m:i:n:p:w"}, ""},
		{[]string{cmdName, "init", "-d"}, ""},
		{[]string{cmdName, "start", "-c", startYaml, "-b", "admin:admin"}, ""},
	}

	for _, v := range validCases {
		checkTest(&v, t)
	}
}

// Test to check that config and datasource files are created in correct location
// based on the arguments passed to the fabric-ca-server and environment variables
func TestDBLocation(t *testing.T) {
	blockingStart = false
	envs := []string{"FABRIC_CA_SERVER_HOME", "FABRIC_CA_HOME", "CA_CFG_PATH",
		"FABRIC_CA_SERVER_DB_DATASOURCE"}
	for _, env := range envs {
		os.Unsetenv(env)
	}

	// Invoke server with -c arg set to serverConfig/config.yml (relative path)
	cfgFile := "serverConfig/config.yml"
	dsFile := "serverConfig/fabric-ca-server.db"
	args := TestData{[]string{cmdName, "start", "-b", "admin:admin", "-c", cfgFile, "-p", "7091"}, ""}
	checkConfigAndDBLoc(t, args, cfgFile, dsFile)
	os.RemoveAll("serverConfig")

	// Invoke server with -c arg set to serverConfig1/config.yml (relative path)
	// and FABRIC_CA_SERVER_DB_DATASOURCE env variable set to fabric-ca-srv.db (relative path)
	os.Setenv("FABRIC_CA_SERVER_DB_DATASOURCE", "fabric-ca-srv.db")
	cfgFile = "serverConfig1/config.yml"
	dsFile = "serverConfig1/fabric-ca-srv.db"
	args = TestData{[]string{cmdName, "start", "-b", "admin:admin", "-c", cfgFile, "-p", "7092"}, ""}
	checkConfigAndDBLoc(t, args, cfgFile, dsFile)
	os.RemoveAll("serverConfig1")

	// Invoke server with -c arg set to serverConfig2/config.yml (relative path)
	// and FABRIC_CA_SERVER_DB_DATASOURCE env variable set to /tmp/fabric-ca-srv.db (absolute path)
	cfgFile = "serverConfig2/config.yml"
	dsFile = os.TempDir() + "/fabric-ca-srv.db"
	os.Setenv("FABRIC_CA_SERVER_DB_DATASOURCE", dsFile)
	args = TestData{[]string{cmdName, "start", "-b", "admin:admin", "-c", cfgFile, "-p", "7093"}, ""}
	checkConfigAndDBLoc(t, args, cfgFile, dsFile)
	os.RemoveAll("serverConfig2")
	os.Remove(dsFile)

	// Invoke server with -c arg set to /tmp/config/config.yml (absolute path)
	// and FABRIC_CA_SERVER_DB_DATASOURCE env variable set to fabric-ca-srv.db (relative path)
	cfgDir := os.TempDir() + "/config/"
	cfgFile = cfgDir + "config.yml"
	dsFile = "fabric-ca-srv.db"
	os.Setenv("FABRIC_CA_SERVER_DB_DATASOURCE", dsFile)
	args = TestData{[]string{cmdName, "start", "-b", "admin:admin", "-c", cfgFile, "-p", "7094"}, ""}
	checkConfigAndDBLoc(t, args, cfgFile, cfgDir+dsFile)
	os.RemoveAll(os.TempDir() + "/config")

	// Invoke server with -c arg set to /tmp/config/config.yml (absolute path)
	// and FABRIC_CA_SERVER_DB_DATASOURCE env variable set to /tmp/fabric-ca-srv.db (absolute path)
	cfgFile = os.TempDir() + "/config/config.yml"
	dsFile = os.TempDir() + "/fabric-ca-srv.db"
	os.Setenv("FABRIC_CA_SERVER_DB_DATASOURCE", dsFile)
	args = TestData{[]string{cmdName, "start", "-b", "admin:admin", "-c", cfgFile, "-p", "7095"}, ""}
	checkConfigAndDBLoc(t, args, cfgFile, dsFile)
	os.RemoveAll(os.TempDir() + "/config")
	os.Remove(dsFile)
	os.Unsetenv("FABRIC_CA_SERVER_DB_DATASOURCE")
}

func TestDefaultMultiCAs(t *testing.T) {
	blockingStart = false

	err := RunMain([]string{cmdName, "start", "-p", "7055", "-c", startYaml, "-d", "-b", "user:pass", "--cacount", "4"})
	if err != nil {
		t.Error("Failed to start server with multiple default CAs using the --cacount flag from command line: ", err)
	}

	if !util.FileExists("ca/ca4/fabric-ca-server_ca4.db") {
		t.Error("Failed to create 4 default CA instances")
	}

	os.RemoveAll("ca")
}

func TestCACountWithAbsPath(t *testing.T) {
	testDir := "myTestDir"
	defer os.RemoveAll(testDir)
	// Run init to create the ca-cert.pem
	err := RunMain([]string{cmdName, "init", "-H", testDir, "-b", "user:pass"})
	if err != nil {
		t.Fatalf("Failed to init CA: %s", err)
	}
	// Set the complete path to the ca-cert.pem file
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %s", err)
	}
	certFilePath := path.Join(cwd, testDir, "ca-cert.pem")
	// Init again with the absolute path to ca-cert.pem and --cacount to make sure this works
	err = RunMain([]string{cmdName, "init", "-H", testDir, "--ca.certfile", certFilePath, "--cacount", "2"})
	if err != nil {
		t.Fatalf("Failed to init multi CA with absolute path: %s", err)
	}
}

func TestMultiCA(t *testing.T) {
	blockingStart = false

	cleanUpMultiCAFiles()
	defer cleanUpMultiCAFiles()

	err := RunMain([]string{cmdName, "start", "-d", "-p", "7056", "-c", "../../testdata/test.yaml", "-b", "user:pass", "--cafiles", "ca/rootca/ca1/fabric-ca-server-config.yaml", "--cafiles", "ca/rootca/ca2/fabric-ca-server-config.yaml"})
	if err != nil {
		t.Error("Failed to start server with multiple CAs using the --cafiles flag from command line: ", err)
	}

	if !util.FileExists("../../testdata/ca/rootca/ca2/fabric-ca2-server.db") {
		t.Error("Failed to create 2 CA instances")
	}

	err = RunMain([]string{cmdName, "start", "-d", "-p", "7056", "-c", "../../testdata/test.yaml", "-b", "user:pass", "--cacount", "1", "--cafiles", "ca/rootca/ca1/fabric-ca-server-config.yaml", "--cafiles", "ca/rootca/ca2/fabric-ca-server-config.yaml"})
	if err == nil {
		t.Error("Should have failed to start server, can't specify values for both --cacount and --cafiles")
	}
}

// Tests to see that the bootstrap by default has permission to register any attibute
func TestRegistrarAttribute(t *testing.T) {
	var err error
	blockingStart = false

	err = os.Setenv("FABRIC_CA_SERVER_HOME", "testregattr/server")
	if !assert.NoError(t, err, "Failed to set environment variable") {
		t.Fatal("Failed to set environment variable")
	}

	args := TestData{[]string{cmdName, "start", "-b", "admin:admin", "-p", "7096", "-d"}, ""}
	os.Args = args.input
	scmd := NewCommand(args.input[1], blockingStart)
	// Execute the command
	err = scmd.Execute()
	if !assert.NoError(t, err, "Failed to start server") {
		t.Fatal("Failed to start server")
	}

	client := getTestClient(7096, "testregattr/client")

	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "admin",
	})
	if !assert.NoError(t, err, "Failed to enroll 'admin'") {
		t.Fatal("Failed to enroll 'admin'")
	}

	adminIdentity := resp.Identity

	_, err = adminIdentity.Register(&api.RegistrationRequest{
		Name: "testuser",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Revoker",
				Value: "true",
			},
			api.Attribute{
				Name:  "hf.IntermediateCA",
				Value: "true",
			},
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer,client",
			},
		},
	})
	assert.NoError(t, err, "Bootstrap user 'admin' should have been able to register a user with attributes")
}

// TestTLSEnabledButCertfileNotSpecified tests if the server with default config starts
// fine with --tls.enabled and with or without --tls.certfile flag. When
// --tls.certfile is not specified, it should use default name 'tls-cert.pem'
func TestTLSEnabledButCertfileNotSpecified(t *testing.T) {
	blockingStart = false
	rootHomeDir := "tlsintCATestRootSrvHome"
	err := os.RemoveAll(rootHomeDir)
	if err != nil {
		t.Fatalf("Failed to remove directory %s: %s", rootHomeDir, err)
	}
	defer os.RemoveAll(rootHomeDir)

	err = RunMain([]string{cmdName, "start", "-p", "7100", "-H", rootHomeDir, "-d", "-b", "admin:admin", "--tls.enabled"})
	if err != nil {
		t.Error("Server should not have failed to start when TLS is enabled and TLS cert file name is not specified...it should have used default TLS cert file name 'tls-cert.pem'", err)
	}

	// start the root server with TLS enabled
	err = RunMain([]string{cmdName, "start", "-p", "7101", "-H", rootHomeDir, "-d", "-b", "admin:admin", "--tls.enabled",
		"--tls.certfile", "tls-cert.pem"})
	if err != nil {
		t.Error("Server should not have failed to start when TLS is enabled and TLS cert file name is specified.", err)
	}
}

func TestVersion(t *testing.T) {
	err := RunMain([]string{cmdName, "version"})
	if err != nil {
		t.Error("Failed to get fabric-ca-server version: ", err)
	}
}

func TestServerLogLevelCLI(t *testing.T) {
	// Not passing in -b flag, don't need for the server to completely start to
	// verify that the log level is correctly getting set
	RunMain([]string{cmdName, "start", "--loglevel", "info"})
	assert.Equal(t, log.Level, log.LevelInfo)

	RunMain([]string{cmdName, "start", "--loglevel", "debug"})
	assert.Equal(t, log.Level, log.LevelDebug)

	RunMain([]string{cmdName, "start", "--loglevel", "warning"})
	assert.Equal(t, log.Level, log.LevelWarning)

	RunMain([]string{cmdName, "start", "--loglevel", "fatal"})
	assert.Equal(t, log.Level, log.LevelFatal)

	RunMain([]string{cmdName, "start", "--loglevel", "critical"})
	assert.Equal(t, log.Level, log.LevelCritical)
}

func TestServerLogLevelEnvVar(t *testing.T) {
	// Not passing in -b flag, don't need for the server to completely start to
	// verify that the log level is correctly getting set
	os.Setenv("FABRIC_CA_SERVER_LOGLEVEL", "info")
	RunMain([]string{cmdName, "start"})
	assert.Equal(t, log.LevelInfo, log.Level)

	os.Setenv("FABRIC_CA_SERVER_LOGLEVEL", "debug")
	RunMain([]string{cmdName, "start"})
	assert.Equal(t, log.LevelDebug, log.Level)

	os.Setenv("FABRIC_CA_SERVER_LOGLEVEL", "warning")
	RunMain([]string{cmdName, "start"})
	assert.Equal(t, log.LevelWarning, log.Level)

	os.Setenv("FABRIC_CA_SERVER_LOGLEVEL", "fatal")
	RunMain([]string{cmdName, "start"})
	assert.Equal(t, log.LevelFatal, log.Level)

	os.Setenv("FABRIC_CA_SERVER_LOGLEVEL", "critical")
	RunMain([]string{cmdName, "start"})
	assert.Equal(t, log.LevelCritical, log.Level)
}

// Run server with specified args and check if the configuration and datasource
// files exist in the specified locations
func checkConfigAndDBLoc(t *testing.T, args TestData, cfgFile string, dsFile string) {
	checkTest(&args, t)
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		t.Errorf("Server configuration file is not found in the expected location: %v, TestData: %v",
			err.Error(), args)
	} else if _, err := os.Stat(dsFile); os.IsNotExist(err) {
		t.Errorf("Datasource is not located in the location %s: %v, TestData: %v",
			dsFile, err.Error(), args)
	}
}

func TestClean(t *testing.T) {
	defYaml := util.GetDefaultConfigFile(cmdName)
	os.Remove(defYaml)
	os.Remove(initYaml)
	os.Remove(startYaml)
	os.Remove(badSyntaxYaml)
	os.Remove(fmt.Sprintf("/tmp/%s.yaml", longFileName))
	os.Remove(unsupportedFileType)
	os.Remove("ca-key.pem")
	os.Remove("ca-cert.pem")
	os.Remove("IssuerSecretKey")
	os.Remove("IssuerPublicKey")
	os.Remove("IssuerRevocationPublicKey")
	os.Remove("fabric-ca-server.db")
	os.RemoveAll("keystore")
	os.RemoveAll("msp")
	os.RemoveAll("../../testdata/msp")
	os.Remove("../../testdata/fabric-ca-server.db")
	os.Remove("../../testdata/ca-cert.pem")
	os.Remove("../../testdata/IssuerSecretKey")
	os.Remove("../../testdata/IssuerPublicKey")
	os.Remove("../../testdata/IssuerRevocationPublicKey")
	os.RemoveAll(ldapTestDir)
	os.RemoveAll("testregattr")
}

func cleanUpMultiCAFiles() {
	caFolder := "../../testdata/ca/rootca"
	nestedFolders := []string{"ca1", "ca2"}
	removeFiles := []string{"msp", "ca-cert.pem", "ca-key.pem", "fabric-ca-server.db",
		"fabric-ca2-server.db", "IssuerSecretKey", "IssuerPublicKey", "IssuerRevocationPublicKey"}

	for _, nestedFolder := range nestedFolders {
		path := filepath.Join(caFolder, nestedFolder)
		for _, file := range removeFiles {
			os.RemoveAll(filepath.Join(path, file))
		}
		os.RemoveAll(filepath.Join(path, "msp"))
	}

	os.Remove("../../testdata/test.yaml")
}

func getTestClient(port int, homeDir string) *lib.Client {
	return &lib.Client{
		Config:  &lib.ClientConfig{URL: fmt.Sprintf("http://localhost:%d", port)},
		HomeDir: homeDir,
	}
}

func TestConfigInit(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %s", err)
	}
	certFile := "testdata/tls_server-cert.pem"
	keyFile := "testdata/tls_server-key.pem"
	homeDir := filepath.Join(cwd, "../../")
	absCertFile := filepath.Join(homeDir, certFile)
	absKeyFile := filepath.Join(homeDir, keyFile)

	cases := []struct {
		enabled bool
		cert    string
		key     string
		err     bool
	}{
		{
			enabled: true,
			cert:    certFile,
			key:     keyFile,
			err:     true,
		},
		{
			enabled: true,
			cert:    "noexit.pem",
			key:     keyFile,
			err:     false,
		},
		{
			enabled: true,
			cert:    certFile,
			key:     "noexit.pem",
			err:     false,
		},
		{
			enabled: false,
			cert:    certFile,
			key:     keyFile,
			err:     true,
		},
		{
			enabled: true,
			cert:    absCertFile,
			key:     absKeyFile,
			err:     true,
		},
	}

	for _, tt := range cases {
		var s ServerCmd
		s.cfg = &lib.ServerConfig{}
		s.homeDirectory = homeDir
		s.myViper = viper.New()
		s.myViper.SetEnvPrefix(envVarPrefix)
		s.myViper.Set("operations.tls.enabled", tt.enabled)
		s.myViper.Set("operations.tls.cert.file", tt.cert)
		s.myViper.Set("operations.tls.key.file", tt.key)
		s.myViper.Set("boot", "user:pass")
		err := s.configInit()
		if err != nil && tt.err {
			t.Error(err)
		}
		defYaml := util.GetDefaultConfigFile(cmdName)
		os.Remove(defYaml)
	}
}

func TestOperationsTLSCertKeyConfig(t *testing.T) {
	certFile := "tls_server-cert.pem"
	keyFile := "tls_server-key.pem"

	cmd := &ServerCmd{
		myViper:     viper.New(),
		cfgFileName: "../../testdata/testviperunmarshal.yaml",
		cfg:         &lib.ServerConfig{},
	}
	cmd.myViper.Set("boot", "user:pass")

	err := cmd.configInit()
	if err != nil {
		t.Error(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %s", err)
	}
	homeDir := filepath.Join(cwd, "../../testdata")

	assert.Equal(t, cmd.cfg.Operations.TLS.CertFile, filepath.Join(homeDir, certFile))
	assert.Equal(t, cmd.cfg.Operations.TLS.KeyFile, filepath.Join(homeDir, keyFile))
}
