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

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/util"
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

// TestCreateDefaultConfigFile test to make sure default config file gets generated correctly
func TestCreateDefaultConfigFile(t *testing.T) {
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml)

	enrollURL := "http://admin:admin2@localhost:7058"

	err := RunMain([]string{cmdName, "enroll", "-u", enrollURL, "-m", myhost})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
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

	err := srv.RegisterBootstrapUser("admin", "adminpw", "banks.bank_a.Dep1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "banks.bank_a")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	aff := make(map[string]interface{})
	aff["banks"] = []string{"bank_a", "bank_b", "bank_c"}

	srv.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	testConfigFileTypes(t)
	testGetCACert(t)
	testEnroll(t)
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

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin:adminpw@localhost:7054"})
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

// TestReenroll tests fabric-ca-client reenroll
func testReenroll(t *testing.T) {
	t.Log("Testing Reenroll CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "reenroll", "-u", "http://localhost:7054", "--enrollment.hosts", "host1,host2"})
	if err != nil {
		t.Errorf("client reenroll --url -f failed: %s", err)
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
	os.Setenv("FABRIC_CA_CLIENT_ID_AFFILIATION", "banks.bank_b")
	os.Setenv("FABRIC_CA_CLIENT_ID_TYPE", "client")

	err := RunMain([]string{cmdName, "register"})
	if err != nil {
		t.Errorf("client register failed using environment variables: %s", err)
	}

	os.Unsetenv("FABRIC_CA_CLIENT_ID_NAME")
	os.Unsetenv("FABRIC_CA_CLIENT_TLS_ID_GROUP")
	os.Unsetenv("FABRIC_CA_CLIENT_TLS_ID_TYPE")

	os.Remove(defYaml)
}

// testRegisterCommandLine tests fabric-ca-client register using command line input
func testRegisterCommandLine(t *testing.T) {
	t.Log("Testing Register CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister3", "--id.affiliation", "banks.bank_a", "--id.type", "client", "--id.attr", "hf.test=a=b"})
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

	aki = strings.ToUpper(aki)

	// Revoker's affiliation: banks.bank_a
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "nonexistinguser"})
	if err == nil {
		t.Errorf("Non existing user being revoked, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "", "-s", serial})
	if err == nil {
		t.Errorf("Only serial specified, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "", "-s", "", "-a", aki})
	if err == nil {
		t.Errorf("Only aki specified, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-s", serial, "-a", aki})
	if err != nil {
		t.Errorf("client revoke -u -s -a failed: %s", err)
	}

	serial, aki, err = getSerialAKIByID("testRegister")
	if err != nil {
		t.Error(err)
	}

	// Revoked user's affiliation: banks.bank_c
	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-s", serial, "-a", aki})
	if err != nil {
		t.Errorf("Revoker does not have the correct affiliation to revoke, should have failed")
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "testRegister3", "-s", "", "-a", ""})
	if err != nil {
		t.Errorf("client revoke -u -e failed: %s", err)
	}

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "testRegister2", "-s", "", "-a", ""})
	if err == nil {
		t.Errorf("Revoker does not have the correct affiliation to revoke, should have failed")
	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7055"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")

	}

	os.RemoveAll(filepath.Dir(defYaml))
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

func TestCleanUp(t *testing.T) {
	os.Remove("../../testdata/cert.pem")
	os.Remove("../../testdata/key.pem")
	os.Remove(testYaml)
	os.Remove(fabricCADB)
	os.RemoveAll(mspDir)
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
	}
}

func getServerConfig() *lib.ServerConfig {
	return &lib.ServerConfig{
		Debug: true,
		Port:  7054,
		CA: lib.ServerConfigCA{
			Keyfile:  keyfile,
			Certfile: certfile,
		},
		CSR: csr.CertificateRequest{
			CN: "TestCN",
		},
	}
}

func getSerialAKIByID(id string) (serial, aki string, err error) {
	testdb, _, _ := dbutil.NewUserRegistrySQLLite3(srv.Config.DB.Datasource)
	acc := lib.NewCertDBAccessor(testdb)

	certs, _ := acc.GetCertificatesByID("admin")

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
