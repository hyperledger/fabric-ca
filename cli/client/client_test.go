/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package client

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/cli/server"
)

var serverStarted bool
var serverExitCode = 0
var dir string

var (
	tdDir        = "../../testdata"
	cfgFile      = "testconfig.json"
	fabricCADB   = path.Join(tdDir, "fabric-ca.db")
	clientConfig = path.Join(tdDir, "client-config.json")
	rrFile       = path.Join(tdDir, "registerrequest.json")
)

// TestNewClient tests constructing a client with a client config provided
func TestNewClient(t *testing.T) {
	loadMyIdentity := true
	_, _, err := loadClient(loadMyIdentity, clientConfig)
	if err != nil {
		t.Errorf("Failed to create a client: %s", err)
	}
}

// TestNewClient tests constructing a client without a client config provided, will use default values
func TestNewClientNoConfig(t *testing.T) {
	loadMyIdentity := true
	_, _, err := loadClient(loadMyIdentity, "")
	if err != nil {
		t.Errorf("Failed to create a client: %s", err)
	}
}

func TestEnrollCLI(t *testing.T) {
	startServer()

	os.Args = []string{"client", "enroll", "-config", clientConfig, "admin", "adminpw"}

	err := Command()
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestReenrollCLI(t *testing.T) {

	os.Args = []string{"client", "reenroll", "-config", clientConfig}

	err := Command()
	if err != nil {
		t.Error("Failed to reenroll, err: ", err)
	}

}

func TestRegister(t *testing.T) {

	os.Args = []string{"client", "register", "-config", clientConfig, rrFile}

	err := Command()
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestRegisterNotEnoughArgs(t *testing.T) {

	os.Args = []string{"client", "register", "-config", clientConfig, rrFile}

	err := Command()
	if err == nil {
		t.Error("Should have failed, not enough arguments provided")
	}

}

func TestRegisterNoJSON(t *testing.T) {

	os.Args = []string{"client", "register", "-config", clientConfig, "", "admin"}

	err := Command()
	if err == nil {
		t.Error("Should result in failure if registration json file not specificied, error: ", err)
	}

}

func TestRegisterMissingRegistrar(t *testing.T) {
	os.Args = []string{"client", "register", "-config", clientConfig, "", ""}

	err := Command()
	if err == nil {
		t.Error("Should result in failure if no registrar identity exists")
	}

}

func TestRevoke(t *testing.T) {

	os.Args = []string{"client", "revoke", "-config", clientConfig, "admin"}

	err := Command()
	if err != nil {
		t.Errorf("TestRevoke failed: %s", err)
	}

}

func TestEnrollCLINotEnoughArgs(t *testing.T) {

	os.Args = []string{"client", "enroll", "-config", clientConfig, "testUser"}

	err := Command()
	if err == nil {
		t.Error("Should have failed, not enough argument provided")
	}

}

func TestEnrollCLIWithCSR(t *testing.T) {

	os.Args = []string{"client", "enroll", "-config", clientConfig, "notadmin", "pass", rrFile}

	err := Command()
	if err != nil {
		t.Error("Failed to enroll, err: ", err)
	}

}

func TestReenrollCLIWithCSR(t *testing.T) {

	os.Args = []string{"client", "reenroll", "-config", clientConfig, rrFile}

	err := Command()
	if err != nil {
		t.Error("Failed to reenroll, err: ", err)
	}
}

func TestRevokeNoArg(t *testing.T) {

	os.Args = []string{"client", "revoke", "-config", clientConfig}

	err := Command()
	if err == nil {
		t.Error("TestRevokeNoArg succeeded but should have failed")
	}
}

func TestRevokeNotAdmin(t *testing.T) {

	os.Args = []string{"client", "revoke", "-config", clientConfig, "admin"}

	err := Command()
	if err == nil {
		t.Error("TestRevokeNotAdmin should have failed but didn't")
	}

}

func TestIncompleteCommand(t *testing.T) {
	os.Args = []string{"client"}

	err := Command()
	if err == nil {
		t.Error("Expected an error stating no command was given")
	}
}

func TestUnsupportedCommand(t *testing.T) {
	os.Args = []string{"client", "unsupportedCMD"}

	err := Command()
	if err == nil {
		t.Error("Expected an error stating command is not defined")
	}
}

func TestBogusCommand(t *testing.T) {
	err := Command()
	if err == nil {
		t.Error("TestBogusCommand passed but should have failed")
	}
}

func TestLast(t *testing.T) {
	// Cleanup
	os.Remove(fabricCADB)
	os.RemoveAll(dir)
}

func runServer() {
	os.Setenv("FABRIC_CA_DEBUG", "true")
	s := new(server.Server)
	s.ConfigDir = tdDir
	s.ConfigFile = cfgFile
	s.StartFromConfig = false
	s.Start()
}

func startServer() {
	var err error
	dir, err = ioutil.TempDir("", "client")
	if err != nil {
		fmt.Printf("Failed to create temp directory [error: %s]", err)
		return
	}

	if !serverStarted {
		os.Remove(fabricCADB)
		os.RemoveAll(dir)
		serverStarted = true
		fmt.Println("starting fabric-ca server ...")
		os.Setenv("CA_CFG_PATH", dir)
		go runServer()
		time.Sleep(10 * time.Second)
		fmt.Println("fabric-ca server started")
	} else {
		fmt.Println("fabric-ca server already started")
	}
}
