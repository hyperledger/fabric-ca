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
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
)

const (
	initYaml  = "i.yaml"
	startYaml = "s.yaml"
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
	err := RunMain(in.input)
	if err != nil {
		t.Errorf("FAILED:\n \tin: %v;\n \tout: %v\n \texpected: SUCCESS\n", in.input, err.Error())
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

func TestErrors(t *testing.T) {
	os.Unsetenv(homeEnvVar)
	_ = ioutil.WriteFile(badSyntaxYaml, []byte("signing: true\n"), 0644)

	errorCases := []TestData{
		{[]string{cmdName, "init", "-c", initYaml}, "option is required"},
		{[]string{cmdName, "init", "-b", "user:pass", "ca.key"}, "too many arguments"},
		{[]string{cmdName, "init", "-b", "user::"}, "Failed to read"},
		{[]string{cmdName, "init", "-c", badSyntaxYaml, "-b", "user:pass"}, "Incorrect format"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", fmt.Sprintf("%s:foo", longUserName)}, "than 1024 characters"},
		{[]string{cmdName, "init", "-c", fmt.Sprintf("%s.yaml", longFileName), "-b", "user:pass"}, "file name too long"},
		{[]string{cmdName, "init", "-c", unsupportedFileType}, "Unsupported Config Type"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", "user"}, "missing a colon"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", "user:"}, "empty password"},
		{[]string{cmdName, "bogus", "-c", initYaml, "-b", "user:pass"}, "unknown command"},
		{[]string{cmdName, "start", "-c"}, "needs an argument:"},
		{[]string{cmdName, "start", "-c", startYaml, "-b", "user:pass", "ca.key"}, "too many arguments"},
	}

	for _, e := range errorCases {
		errorTest(&e, t)
		_ = os.Remove(initYaml)
	}
}

func TestValid(t *testing.T) {
	os.Unsetenv(homeEnvVar)
	blockingStart = false

	os.Setenv("CA_CFG_PATH", ".")
	validCases := []TestData{
		{[]string{cmdName, "init", "-b", "admin:a:d:m:i:n:p:w"}, ""},
		{[]string{cmdName, "init", "-d"}, ""},
		{[]string{cmdName, "start", "-c", startYaml}, ""},
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
	os.Remove(unsupportedFileType)
	os.Remove("ca-key.pem")
	os.Remove("ca-cert.pem")
	os.Remove("fabric-ca-server.db")
}
