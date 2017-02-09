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
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/cli/server"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	testYaml = "test.yaml"
	myhost   = "hostname"
)

var (
	defYaml        string
	tdDir          = "../../testdata"
	cfgFile        = "testconfig.json"
	fabricCADB     = path.Join(tdDir, "fabric-ca.db")
	clientConfig   = path.Join(tdDir, "client-config.json")
	rrFile         = path.Join(tdDir, "registerrequest.json")
	serverStarted  bool
	serverExitCode = 0
)

// TestCreateDefaultConfigFile test to make sure default config file gets generated correctly
func TestCreateDefaultConfigFile(t *testing.T) {
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")
	os.RemoveAll(defYaml)

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

	os.RemoveAll(defYaml)

}

func startServer() {
	if !serverStarted {
		os.Remove(fabricCADB)
		serverStarted = true
		fmt.Println("starting fabric-ca server ...")
		go runServer()
		time.Sleep(10 * time.Second)
		fmt.Println("fabric-ca server started")
	} else {
		fmt.Println("fabric-ca server already started")
	}
}

func runServer() {
	os.Setenv("FABRIC_CA_DEBUG", "true")
	s := new(server.Server)
	s.ConfigDir = tdDir
	s.ConfigFile = cfgFile
	s.StartFromConfig = false
	s.Start()
}

// TestEnroll tests fabric-ca-client enroll
func TestEnroll(t *testing.T) {
	startServer()

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

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "http://admin2:adminpw2@localhost:7054"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	os.Remove(defYaml)

	err = RunMain([]string{cmdName, "enroll", "-u", "http://admin2:adminpw2@localhost:7055"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")
	}

	os.Remove(defYaml)
	os.Remove(testYaml)
}

// TestReenroll tests fabric-ca-client reenroll
func TestReenroll(t *testing.T) {
	t.Log("Testing Reenroll CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "reenroll", "-u", "http://localhost:7054"})
	if err != nil {
		t.Errorf("client reenroll --url -f failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-c", testYaml})
	if err != nil {
		t.Errorf("client reenroll -c failed: %s", err)
	}

	os.Remove(defYaml)
	os.Remove(testYaml)
}

// TestRegister tests fabric-ca-client register
func TestRegister(t *testing.T) {
	t.Log("Testing Register CMD")
	defYaml = util.GetDefaultConfigFile("fabric-ca-client")

	err := RunMain([]string{cmdName, "register", "-c", testYaml})
	if err == nil {
		t.Error("Should have failed, no register request file provided")
	}

	err = RunMain([]string{cmdName, "register", "-f", "../../testdata/registerrequest.json"})
	if err != nil {
		t.Errorf("client register -f failed: %s", err)
	}

	os.Remove(defYaml) // Delete default config file

	err = RunMain([]string{cmdName, "register", "--url", "http://localhost:7055", "-f", "../../testdata/registerrequest.json"})
	if err == nil {
		t.Error("Should have failed, client config file should have incorrect port (7055) for server")
	}

	os.Remove(defYaml)
	os.Remove(testYaml)
}

// TestRevoke tests fabric-ca-client revoke
func TestRevoke(t *testing.T) {
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
	os.Remove(testYaml)
}

// TestBogus tests a negative test case
func TestBogus(t *testing.T) {
	err := RunMain([]string{cmdName, "bogus"})
	if err == nil {
		t.Errorf("client bogus passed but should have failed")
	}
}

func TestCleanUp(t *testing.T) {
	os.Remove("cert.pem")
	os.Remove("key.pem")
	os.Remove(fabricCADB)
}
