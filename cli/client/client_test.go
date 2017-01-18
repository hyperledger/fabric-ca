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
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/hyperledger/fabric-ca/cli/server"
)

var serverStarted bool
var serverExitCode = 0
var dir string

const (
	ClientTLSConfig = "client-config.json"
	FabricCADB      = "../../testdata/fabric-ca.db"
)

// TestNewClient tests constructing a client
func TestNewClient(t *testing.T) {
	_, err := NewClient("https://127.0.0.1:8888")
	if err != nil {
		t.Errorf("Failed to create a client: %s", err)
	}
}

func TestEnrollCLI(t *testing.T) {
	startServer()

	clientConfig := filepath.Join(dir, ClientTLSConfig)
	os.Link("../../testdata/client-config2.json", clientConfig)

	c := new(cli.Config)

	args := []string{"admin", "adminpw", "https://localhost:8888"}

	err := enrollMain(args, *c)
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestReenrollCLI(t *testing.T) {
	c := new(cli.Config)

	args := []string{"https://localhost:8888"}

	err := reenrollMain(args, *c)
	if err != nil {
		t.Error("Failed to reenroll, err: ", err)
	}

}

func TestRegister(t *testing.T) {

	c := new(cli.Config)

	args := []string{"../../testdata/registerrequest.json", "https://localhost:8888"}

	err := registerMain(args, *c)
	if err != nil {
		t.Error("Failed to register, err: ", err)
	}

}

func TestRegisterNotEnoughArgs(t *testing.T) {
	c := new(cli.Config)

	args := []string{"../../testdata/registerrequest.json"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should have failed, not enough arguments provided")
	}

}

func TestRegisterNoJSON(t *testing.T) {
	c := new(cli.Config)

	args := []string{"", "admin", "https://localhost:8888"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should result in failure if registration json file not specificied, error: ", err)
	}

}

func TestRegisterMissingRegistrar(t *testing.T) {
	c := new(cli.Config)

	// os.Setenv("FABRIC_CA_HOME", "/tmp")
	args := []string{"", "", "https://localhost:8888"}

	err := registerMain(args, *c)
	if err == nil {
		t.Error("Should result in failure if no registrar identity exists")
	}

}

func TestRevoke(t *testing.T) {

	c := new(cli.Config)

	args := []string{"https://localhost:8888", "admin"}

	err := revokeMain(args, *c)
	if err != nil {
		t.Errorf("TestRevoke failed: %s", err)
	}

}

func TestEnrollCLINotEnoughArgs(t *testing.T) {

	c := new(cli.Config)

	args := []string{"testUser"}

	err := enrollMain(args, *c)
	if err == nil {
		t.Error("Should have failed, not enough argument provided")
	}

}

func TestEnrollCLIWithCSR(t *testing.T) {

	c := new(cli.Config)

	args := []string{"notadmin", "pass", "https://localhost:8888", "../../testdata/csr.json"}

	err := enrollMain(args, *c)
	if err != nil {
		t.Error("Failed to enroll, err: ", err)
	}

}

func TestReenrollCLIWithCSR(t *testing.T) {

	c := new(cli.Config)

	args := []string{"https://localhost:8888", "../../testdata/csr.json"}

	err := reenrollMain(args, *c)
	if err != nil {
		t.Error("Failed to reenroll, err: ", err)
	}
}

func TestRevokeNoArg(t *testing.T) {

	c := new(cli.Config)

	args := []string{"https://localhost:8888"}

	err := revokeMain(args, *c)
	if err == nil {
		t.Error("TestRevokeNoArg succeeded but should have failed")
	}
}

func TestRevokeNotAdmin(t *testing.T) {

	c := new(cli.Config)

	args := []string{"https://localhost:8888", "admin"}

	err := revokeMain(args, *c)
	if err == nil {
		t.Error("TestRevokeNotAdmin should have failed but didn't")
	}

	// os.RemoveAll(clientPath)
}

func TestBogusCommand(t *testing.T) {
	err := Command()
	if err == nil {
		t.Error("TestBogusCommand passed but should have failed")
	}
}

func TestLast(t *testing.T) {
	// Cleanup
	os.Remove(FabricCADB)
	os.RemoveAll(dir)
}

func runServer() {
	os.Setenv("FABRIC_CA_DEBUG", "true")
	server.Start("../../testdata", "testconfig.json")
}

func startServer() {
	var err error
	dir, err = ioutil.TempDir("", "client")
	if err != nil {
		fmt.Printf("Failed to create temp directory [error: %s]", err)
		return
	}

	if !serverStarted {
		os.Remove(FabricCADB)
		os.RemoveAll(dir)
		serverStarted = true
		fmt.Println("starting fabric-ca server ...")
		os.Setenv("FABRIC_CA_HOME", dir)
		go runServer()
		time.Sleep(10 * time.Second)
		fmt.Println("fabric-ca server started")
	} else {
		fmt.Println("fabric-ca server already started")
	}
}
