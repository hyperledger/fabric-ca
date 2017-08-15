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
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
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
		{[]string{cmdName, "start", "-c", startYaml, "-b", "user:pass", "ca.key"}, "Unrecognized arguments found"},
	}

	for _, e := range errorCases {
		errorTest(&e, t)
		_ = os.Remove(initYaml)
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

	if !util.FileExists("ca/ca4/fabric-ca-server.db") {
		t.Error("Failed to create 4 default CA instances")
	}

	os.RemoveAll("ca")
}

func TestMultiCA(t *testing.T) {
	blockingStart = false

	err := RunMain([]string{cmdName, "start", "-d", "-p", "7056", "-c", "../../testdata/test.yaml", "-b", "user:pass", "--cacount", "0", "--cafiles", "ca/rootca/ca1/fabric-ca-server-config.yaml", "--cafiles", "ca/rootca/ca2/fabric-ca-server-config.yaml"})
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

	cleanUpMultiCAFiles()
}

func TestVersion(t *testing.T) {
	err := RunMain([]string{cmdName, "version"})
	if err != nil {
		t.Error("Failed to get fabric-ca-server version: ", err)
	}
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
	os.Remove("fabric-ca-server.db")
	os.RemoveAll("keystore")
	os.RemoveAll("msp")
	os.RemoveAll("../../testdata/msp")
	os.Remove("../../testdata/fabric-ca-server.db")
	os.Remove("../../testdata/ca-cert.pem")
	os.RemoveAll(ldapTestDir)
}

func cleanUpMultiCAFiles() {
	caFolder := "../../testdata/ca/rootca"
	nestedFolders := []string{"ca1", "ca2"}
	removeFiles := []string{"msp", "ca-cert.pem", "ca-key.pem", "fabric-ca-server.db", "fabric-ca2-server.db"}

	for _, nestedFolder := range nestedFolders {
		path := filepath.Join(caFolder, nestedFolder)
		for _, file := range removeFiles {
			os.RemoveAll(filepath.Join(path, file))
		}
		os.RemoveAll(filepath.Join(path, "msp"))
	}

	os.Remove("../../testdata/test.yaml")
}
