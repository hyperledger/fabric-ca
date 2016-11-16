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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	cop "github.com/hyperledger/fabric-cop/api"
	server "github.com/hyperledger/fabric-cop/cli/server"
	"github.com/hyperledger/fabric-cop/idp"
)

type Admin struct {
	User       string
	Pass       []byte
	Type       string
	Group      string
	Attributes []idp.Attribute
}

const (
	CERT     string = "../testdata/ec.pem"
	KEY      string = "../testdata/ec-key.pem"
	CFG      string = "../testdata/testconfig.json"
	CSR      string = "../testdata/csr.json"
	REG      string = "../testdata/registerrequest.json"
	DBCONFIG string = "../testdata/enrolltest.json"
)

var (
	Registrar  = Admin{User: "admin", Pass: []byte("adminpw"), Type: "User", Group: "bank_a", Attributes: []idp.Attribute{idp.Attribute{Name: "hf.Registrar.DelegateRoles", Value: "client,validator,auditor"}}}
	testEnroll = cop.RegisterRequest{User: "testEnroll", Type: "client", Group: "bank_a", Attributes: []idp.Attribute{idp.Attribute{Name: "role", Value: "client"}}}
)

var serverStarted bool
var serverExitCode = 0

const (
	enrollPath = "/tmp/enrolltest"
)

// Test the server start command
func TestStartServer(t *testing.T) {
	fmt.Println("running TestStartServer ...")
	os.RemoveAll("/tmp/enrollTest")
	rtn := startServer()
	if rtn != 0 {
		t.Errorf("Failed to start server with return code: %d", rtn)
		t.FailNow()
	}
	fmt.Println("passed TestStartServer")
}

func TestRegister(t *testing.T) {
	fmt.Println("running TestRegister ...")
	r := server.NewRegisterUser()
	metaDataBytes, _ := json.Marshal(testEnroll.Attributes)
	metaData := string(metaDataBytes)
	// user.CallerID = Registrar.User
	_, err := r.RegisterUser(testEnroll.User, testEnroll.Type, testEnroll.Group, metaData, Registrar.User)
	if err != nil {
		fmt.Printf("RegisterUser failed: %s\n", err)
		t.Errorf("Failed to register user: %s, err: %s", testEnroll.User, err)
	}
	fmt.Println("passed TestRegister")
}

func TestEnroll(t *testing.T) {
	fmt.Println("running TestEnroll ...")
	rtn := enroll("admin", "adminpw")
	if rtn != 0 {
		fmt.Printf("enroll failed: rtn=%d\n", rtn)
		t.Errorf("Failed to enroll with return code: %d", rtn)
	}
	fmt.Println("passed TestEnroll")
}

func TestReenroll(t *testing.T) {
	fmt.Println("running TestReenroll ...")
	rtn := reenroll()
	if rtn != 0 {
		fmt.Printf("reenroll failed: rtn=%d\n", rtn)
		t.Errorf("Failed to reenroll with return code: %d", rtn)
	}
	fmt.Println("passed TestReenroll")
}

func TestCFSSL(t *testing.T) {
	fmt.Println("running TestCFSSL ...")
	rtn := cfssl()
	if rtn != 0 {
		fmt.Printf("TestCFSSL failed: rtn=%d\n", rtn)
		t.Errorf("Failed to test CFSSL with return code: %d", rtn)
	}
	fmt.Println("passed TestCFSSL")
}

func TestBogusCommand(t *testing.T) {
	rtn := COPMain([]string{"cop", "bogus"})
	if rtn == 0 {
		t.Error("TestBogusCommand passed but should have failed")
	}
}

func startServer() int {
	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		os.Setenv("COP_HOME", enrollPath)
		go runServer()
		time.Sleep(3 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}

func runServer() {
	os.Setenv("COP_DEBUG", "true")
	os.Setenv("COP_HOME", enrollPath)
	serverExitCode = COPMain([]string{"cop", "server", "start", "-ca", CERT, "-ca-key", KEY, "-config", CFG, "-db-config", DBCONFIG})
}

func enroll(user, pass string) int {
	fmt.Printf("enrolling user '%s' with password '%s' ...\n", user, pass)
	rtn := COPMain([]string{"cop", "client", "enroll", user, pass, "http://localhost:8888", CSR})
	fmt.Printf("enroll result is '%d'\n", rtn)
	return rtn
}

func reenroll() int {
	fmt.Println("reenrolling ...")
	rtn := COPMain([]string{"cop", "client", "reenroll", "http://localhost:8888", CSR})
	fmt.Printf("reenroll result is '%d'\n", rtn)
	return rtn
}

func cfssl() int {
	fmt.Println("cfssl ...")
	rtn := COPMain([]string{"cop", "cfssl", "version"})
	fmt.Printf("cfssl result is '%d'\n", rtn)
	return rtn
}

func register(file string) int {
	fmt.Printf("register file '%s' ...\n", file)
	rtn := COPMain([]string{"cop", "client", "register", file, "http://localhost:8888", "loglevel=0"})
	fmt.Printf("register result is '%d'\n", rtn)
	return rtn
}
