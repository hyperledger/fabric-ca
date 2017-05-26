/*
Copyright IBM Corp. 2017 All Rights Reserved.

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

package main

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

const (
	testYaml             = "../../testdata/test.yaml"
	mspDir               = "../../testdata/msp"
	myhost               = "hostname"
	certfile             = "ec.pem"
	keyfile              = "ec-key.pem"
	tlsCertFile          = "tls_server-cert.pem"
	tlsKeyFile           = "tls_server-key.pem"
	rootCert             = "root.pem"
	tlsClientCertFile    = "tls_client-cert.pem"
	tlsClientCertExpired = "expiredcert.pem"
	tlsClientKeyFile     = "tls_client-key.pem"
	tdDir                = "../../testdata"
	db                   = "fabric-ca-server.db"
	rootCertEnvVar       = "FABRIC_CA_CLIENT_TLS_CERTFILES"
	clientKeyEnvVar      = "FABRIC_CA_CLIENT_TLS_CLIENT_KEYFILE"
	clientCertEnvVar     = "FABRIC_CA_CLIENT_TLS_CLIENT_CERTFILE"
	moptionDir           = "moption-test"
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
	defYaml    string
	fabricCADB = path.Join(tdDir, db)
	srv        *lib.Server
)

type TestData struct {
	input []string // input
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

	enrollURL := "http://admin:admin2@localhost:7058"

	err := RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-m", myhost})
	if err == nil {
		t.Errorf("No server running, should have failed")
	}

	fileBytes, err := ioutil.ReadFile(defYaml)
	if err != nil {
		t.Error(err)
	}

	configFile := string(fileBytes)

	if !strings.Contains(configFile, "localhost:7058") {
		t.Error("Failed to update default config file with url")
	}

	if !strings.Contains(configFile, myhost) {
		t.Error("Failed to update default config file with host name")
	}

	os.Remove(defYaml)

}

func TestClientCommandsNoTLS(t *testing.T) {
	os.Remove(fabricCADB)

	srv = getServer()
	srv.HomeDir = tdDir
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "company1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	aff := make(map[string]interface{})
	aff["hyperledger"] = []string{"org1", "org2", "org3"}
	aff["company1"] = []string{}
	aff["company2"] = []string{}

	srv.CA.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	testConfigFileTypes(t)
	testGetCACert(t)
	testEnroll(t)
	testProfiling(t)
	testRegisterConfigFile(t)
	testRegisterEnvVar(t)
	testRegisterCommandLine(t)
	testRevoke(t)
	testBogus(t)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
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
	err := RunMain([]string{cmdName, "enroll", "-u",
		"http://admin:adminpw@localhost:7054", "-c", "config/client-config.txt"})
	if err == nil {
		t.Errorf("Enroll command invoked with -c config/client-config.txt should have failed: %v",
			err.Error())
	}

	err = RunMain([]string{cmdName, "enroll", "-u",
		"http://admin:adminpw@localhost:7054", "-c", "config/client-config.mf"})
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

	err = RunMain([]string{cmdName, "enroll", "-u",
		"http://admin:adminpw@localhost:7054", "-c", fName})
	if err != nil {
		t.Errorf("Enroll command invoked with -c %s failed: %v",
			fName, err.Error())
	}

	// Reset the config file name
	cfgFileName = util.GetDefaultConfigFile("fabric-ca-client")
	os.RemoveAll("./config")
}

// TestGetCACert tests fabric-ca-client getcacert
func testGetCACert(t *testing.T) {
	t.Log("Testing getcacert")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml) // Clean up any left over config file
	os.RemoveAll("msp")
	err := RunMain([]string{cmdName, "getcacert", "-d", "-u", "http://localhost:7054"})
	if err != nil {
		t.Errorf("getcainfo failed: %s", err)
	}
	err = RunMain([]string{cmdName, "getcacert", "-d", "-u", "http://localhost:9999"})
	if err == nil {
		t.Error("getcacert with bogus URL should have failed but did not")
	}
	err = RunMain([]string{cmdName, "getcacert", "-d"})
	if err == nil {
		t.Error("getcacert with no URL should have failed but did not")
	}
	os.RemoveAll("cacerts")
	os.RemoveAll("msp")
	os.Remove(defYaml)
}

// TestEnroll tests fabric-ca-client enroll
func testEnroll(t *testing.T) {
	t.Log("Testing Enroll CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.Remove(defYaml) // Clean up any left over config file

	// Negative test case, enroll command without username/password
	err := RunMain([]string{cmdName, "enroll", "-d"})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin:adminpw@localhost:7054", "-M", filepath.Join(filepath.Dir(defYaml), "msp")})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	testReenroll(t)

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin2:adminpw2@localhost:7055"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")
	}

	os.Remove(defYaml)
}

// TestMOption tests to make sure that the key is stored in the correct
// directory when the "-M" option is used.
func TestMOption(t *testing.T) {
	os.RemoveAll(moptionDir)
	port := 7173
	s := startServer(path.Join(moptionDir, "server"), port, t)
	if s == nil {
		return
	}
	homedir := path.Join(moptionDir, "client")
	mspdir := "msp2" // relative to homedir
	err := RunMain([]string{
		cmdName, "enroll",
		"-u", fmt.Sprintf("http://admin:adminpw@localhost:%d", port),
		"-c", path.Join(homedir, "config.yaml"),
		"-M", mspdir, "-d"})
	if err != nil {
		t.Fatalf("client enroll -u failed: %s", err)
	}
	keystore := path.Join(homedir, mspdir, "keystore")
	count := getNumFiles(keystore, t)
	if count != 1 {
		t.Fatalf("client enroll -M failed: expecting 1 file in keystore %s but found %d",
			keystore, count)
	}
	s.Stop()
}

// TestReenroll tests fabric-ca-client reenroll
func testReenroll(t *testing.T) {
	t.Log("Testing Reenroll CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "reenroll", "-u", "http://localhost:7054", "--csr.hosts", "host1"})
	if err != nil {
		t.Errorf("client reenroll --url -f failed: %s", err)
	}

	err = util.CheckHostsInCert(filepath.Join(filepath.Dir(defYaml), "msp", "signcerts", "cert.pem"), "host1")
	if err != nil {
		t.Error(err)
	}
	os.Remove(defYaml)
}

// testRegisterConfigFile tests fabric-ca-client register using the config file
func testRegisterConfigFile(t *testing.T) {
	t.Log("Testing Register CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "enroll", "-d", "-c", "../../testdata/fabric-ca-client-config.yaml", "-u", "http://admin2:adminpw2@localhost:7054"})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-d", "-c", "../../testdata/fabric-ca-client-config.yaml"})
	if err != nil {
		t.Errorf("client register failed using config file: %s", err)
	}

	os.Remove(defYaml)
}

// testRegisterEnvVar tests fabric-ca-client register using environment variables
func testRegisterEnvVar(t *testing.T) {
	t.Log("Testing Register CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.Setenv("FABRIC_CA_CLIENT_ID_NAME", "testRegister2")
	os.Setenv("FABRIC_CA_CLIENT_ID_AFFILIATION", "company1")
	os.Setenv("FABRIC_CA_CLIENT_ID_TYPE", "client")

	err := RunMain([]string{cmdName, "register"})
	if err != nil {
		t.Errorf("client register failed using environment variables: %s", err)
	}

	os.Unsetenv("FABRIC_CA_CLIENT_ID_NAME")
	os.Unsetenv("FABRIC_CA_CLIENT_ID_AFFILIATION")
	os.Unsetenv("FABRIC_CA_CLIENT_TLS_ID_TYPE")

	os.Remove(defYaml)
}

// testRegisterCommandLine tests fabric-ca-client register using command line input
func testRegisterCommandLine(t *testing.T) {
	t.Log("Testing Register CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister3", "--id.affiliation", "hyperledger.org1", "--id.type", "client", "--id.attrs", "foo=a=b bar=c"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister4", "--id.affiliation", "company2", "--id.type", "client"})
	if err != nil {
		t.Errorf("client register failed: %s", err)
	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "register", "-u", "http://localhost:7055"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")
	}

	os.Remove(defYaml)
}

// TestRevoke tests fabric-ca-client revoke
func testRevoke(t *testing.T) {
	t.Log("Testing Revoke CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.Remove(defYaml) // Delete default config file

	err := RunMain([]string{cmdName, "revoke"})
	if err == nil {
		t.Errorf("No enrollment ID or serial/aki provided, should have failed")
	}

	serial, aki, err := getSerialAKIByID("admin")
	if err != nil {
		t.Error(err)
	}

	// Revoker's affiliation: company1
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "--revoke.name", "nonexistinguser"})
	if err == nil {
		t.Errorf("Non existing user being revoked, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "--revoke.name", "", "--revoke.serial", serial})
	if err == nil {
		t.Errorf("Only serial specified, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "--revoke.name", "", "--revoke.serial", "", "--revoke.aki", aki})
	if err == nil {
		t.Errorf("Only aki specified, should have failed")
	}

	// revoker's affiliation: company1, revoking affiliation: ""
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "--revoke.serial", serial, "--revoke.aki", aki})
	if err == nil {
		t.Error("Should have failed, admin2 cannot revoke root affiliation")
	}

	// When serial, aki and enrollment id are specified in a revoke request,
	// fabric ca server returns an error if the serial and aki do not belong
	// to the enrollment ID.
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "blah", "-s", serial, "-a", aki})
	if err == nil {
		t.Errorf("The Serial and AKI are not associated with the enrollment ID: %s", err)
	}

	// Revoked user's affiliation: hyperledger.org3
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "--revoke.name", "testRegister3", "--revoke.serial", "", "--revoke.aki", ""})
	if err == nil {
		t.Error("Should have failed, admin2 does not have authority revoke")
	}

	// testRegister2's affiliation: company1, revoker's affiliation: company1
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "--revoke.name", "testRegister2", "--revoke.serial", "", "--revoke.aki", ""})
	if err != nil {
		t.Errorf("Failed to revoke proper affiliation hierarchy, error: %s", err)
	}

	// testRegister4's affiliation: company2, revoker's affiliation: company1
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "testRegister4", "-s", "", "-a", ""})
	if err == nil {
		t.Error("Should have failed have different affiliation path")
	}

	// Enroll admin with root affiliation and test revoking with root
	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin:adminpw@localhost:7054"})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	// testRegister4's affiliation: company2, revoker's affiliation: "" (root)
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "--revoke.name", "testRegister4", "--revoke.serial", "", "--revoke.aki", ""})
	if err != nil {
		t.Errorf("User with root affiliation failed to revoke, error: %s", err)

	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7055"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")

	}

	os.RemoveAll(filepath.Dir(defYaml))

}

// testProfiling tests enablement of fabric CA client heap/cpu profiling
func testProfiling(t *testing.T) {
	t.Log("Testing profiling")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	var testCases = []struct {
		pEnvVal       string
		input         []string
		mProfExpected bool
		cProfExpected bool
	}{
		{"heap", []string{cmdName, "reenroll", "-u", "http://localhost:7054"}, true, false},
		{"cpu", []string{cmdName, "reenroll", "-u", "http://localhost:7054"}, false, true},
		{"", []string{cmdName, "reenroll", "-u", "http://localhost:7054"}, false, false},
		{"xxx", []string{cmdName, "reenroll", "-u", "http://localhost:7054"}, false, false},
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
		if profileInst != nil {
			profileInst.Stop()
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

func TestClientCommandsUsingConfigFile(t *testing.T) {
	os.Remove(fabricCADB)

	srv = getServer()
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
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

	err = RunMain([]string{cmdName, "enroll", "-c", "../../testdata/fabric-ca-client-config.yaml", "-u", "https://admin:adminpw@localhost:7054", "-d"})
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

	srv = getServer()
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "bank1")
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

	err = RunMain([]string{cmdName, "enroll", "-d", "-c", testYaml, "-u", "https://admin:adminpw@localhost:7054", "-d"})
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

	srv = getServer()
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "bank1")
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

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "--tls.certfiles", rootCert, "--tls.client.keyfile", tlsClientKeyFile, "--tls.client.certfile", tlsClientCertFile, "-u", "https://admin:adminpw@localhost:7054", "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "--tls.certfiles", rootCert, "--tls.client.keyfile", tlsClientKeyFile, "--tls.client.certfile", tlsClientCertExpired, "-u", "https://admin:adminpw@localhost:7054", "-d"})
	if err == nil {
		t.Errorf("Expired certificate used for TLS connection, should have failed")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestMultiCA(t *testing.T) {
	cleanMultiCADir()

	srv = getServer()
	srv.HomeDir = "../../testdata"
	srv.Config.CAfiles = []string{"ca/rootca/ca1/fabric-ca-server-config.yaml", "ca/rootca/ca2/fabric-ca-server-config.yaml"}
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
	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "http://admin:adminpw@localhost:7054", "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "http://adminca1:adminca1pw@localhost:7054", "-d", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-c", testYaml, "-d", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-c", testYaml, "-d", "--id.name", "testuser", "--id.type", "user", "--id.affiliation", "org1", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "revoke", "-c", testYaml, "-d", "--revoke.name", "adminca1", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "getcacert", "-c", testYaml, "-d", "--caname", "rootca1"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "http://admin:adminpw@localhost:7054", "-d", "--caname", "rootca2"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "http://adminca1:adminca1pw@localhost:7054", "-d", "--caname", "rootca3"})
	if err == nil {
		t.Errorf("Should have failed, rootca3 does not exist on server")
	}

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestCleanUp(t *testing.T) {
	os.Remove("../../testdata/ca-cert.pem")
	os.Remove("../../testdata/ca-key.pem")
	os.Remove(testYaml)
	os.Remove(fabricCADB)
	os.RemoveAll(mspDir)
	os.RemoveAll(moptionDir)
	cleanMultiCADir()
}

func cleanMultiCADir() {
	caFolder := "../../testdata/ca/rootca"
	nestedFolders := []string{"ca1", "ca2"}
	removeFiles := []string{"ec.pem", "ec-key.pem", "fabric-ca-server.db", "fabric-ca2-server.db", "ca-chain.pem"}

	for _, nestedFolder := range nestedFolders {
		path := filepath.Join(caFolder, nestedFolder)
		for _, file := range removeFiles {
			os.Remove(filepath.Join(path, file))
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
		Port:  7054,
	}
}

func getCAConfig() *lib.CAConfig {
	affiliations := map[string]interface{}{
		"org1": nil,
	}

	defaultSigningProfile := &config.SigningProfile{
		Usage:        []string{"cert sign"},
		ExpiryString: "8000h",
		Expiry:       time.Hour * 8000,
	}

	profiles := map[string]*config.SigningProfile{
		"ca": defaultSigningProfile,
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
		Signing: &config.Signing{
			Default:  defaultSigningProfile,
			Profiles: profiles,
		},
	}
}

func getSerialAKIByID(id string) (serial, aki string, err error) {
	testdb, _, _ := dbutil.NewUserRegistrySQLLite3(srv.CA.Config.DB.Datasource)
	acc := lib.NewCertDBAccessor(testdb)

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

func extraArgErrorTest(in *TestData, t *testing.T) {
	err := RunMain(in.input)
	if err == nil {
		assert.Error(t, errors.New("Should have resulted in an error as extra agruments provided"))
	}
	if err != nil {
		if !strings.Contains(err.Error(), "Extra arguments") {
			assert.Error(t, fmt.Errorf("Failed for other reason besides extra argument: %s", err))
		}
	}
}

// get the number of files in a directory
func getNumFiles(dir string, t *testing.T) int {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatalf("Failed to get number of files in directory '%s': %s", dir, err)
	}
	return len(files)
}

func startServer(home string, port int, t *testing.T) *lib.Server {
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
