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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	testYaml          = "../../testdata/test.yaml"
	myhost            = "hostname"
	certfile          = "ec.pem"
	keyfile           = "ec-key.pem"
	tlsCertFile       = "tls_server-cert.pem"
	tlsKeyFile        = "tls_server-key.pem"
	rootCert          = "root.pem"
	tlsClientCertFile = "tls_client-cert.pem"
	tlsClientKeyFile  = "tls_client-key.pem"
	tdDir             = "../../testdata"
	db                = "fabric-ca-server.db"
	rootCertEnvVar    = "FABRIC_CA_CLIENT_TLS_CERTFILES"
	clientKeyEnvVar   = "FABRIC_CA_CLIENT_TLS_CLIENT_KEYFILE"
	clientCertEnvVar  = "FABRIC_CA_CLIENT_TLS_CLIENT_CERTFILE"
)

var (
	defYaml    string
	fabricCADB = path.Join(tdDir, db)
)

// TestCreateDefaultConfigFile test to make sure default config file gets generated correctly
func TestCreateDefaultConfigFile(t *testing.T) {
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.Remove(defYaml)

	fabricCAServerURL := "http://localhost:7058"

	err := RunMain([]string{cmdName, "enroll", "-u", fabricCAServerURL, "-m", myhost})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	fileBytes, err := ioutil.ReadFile(defYaml)
	if err != nil {
		t.Error(err)
	}

	configFile := string(fileBytes)

	if !strings.Contains(configFile, fabricCAServerURL) {
		t.Error("Failed to update default config file with url")
	}

	if !strings.Contains(configFile, myhost) {
		t.Error("Failed to update default config file with host name")
	}

	os.Remove(defYaml)

}

func TestClientCommandsNoTLS(t *testing.T) {
	os.Remove(fabricCADB)

	srv := getServer()
	srv.HomeDir = tdDir
	srv.Config.Debug = true

	err := srv.RegisterBootstrapUser("admin", "adminpw", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	err = srv.RegisterBootstrapUser("admin2", "adminpw2", "bank1")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
	}

	aff := make(map[string]interface{})
	aff["bank_a"] = "banks"

	srv.Config.Affiliations = aff

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	testEnroll(t)
	testReenroll(t)
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

// TestEnroll tests fabric-ca-client enroll
func testEnroll(t *testing.T) {
	t.Log("Testing Enroll CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	os.RemoveAll(defYaml) // Clean up any left over config file

	// Negative test case, enroll command without username/password
	err := RunMain([]string{cmdName, "enroll", "-d"})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin:adminpw@localhost:7054"})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	os.Remove(defYaml)

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

	err := RunMain([]string{cmdName, "reenroll", "-u", "http://localhost:7054"})
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
	os.Setenv("FABRIC_CA_CLIENT_ID_GROUP", "bank_a")
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

	err := RunMain([]string{cmdName, "register", "-d", "--id.name", "testRegister3", "--id.group", "bank_a", "--id.type", "client", "--id.attr", "hf.test=a=b"})
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

	err = RunMain([]string{cmdName, "revoke", "-u", "http://localhost:7054", "-e", "admin"})
	if err != nil {
		t.Errorf("client revoke -u -e failed: %s", err)
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

	srv := getServer()
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

	srv := getServer()
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

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "https://admin:adminpw@localhost:7054", "-d"})
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

	srv := getServer()
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
	srv.Config.TLS.CertFile = "tls_server-cert.pem"
	srv.Config.TLS.KeyFile = "tls_server-key.pem"

	err = srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", "../../testdata/test.yaml", "--tls.certfiles", "root.pem", "--tls.client.keyfile", "tls_client-key.pem", "--tls.client.certfile", "tls_client-cert.pem", "-u", "https://admin:adminpw@localhost:7054", "-d"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
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
}
