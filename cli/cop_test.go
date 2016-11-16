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
	cutil "github.com/hyperledger/fabric-cop/cli/client"
	server "github.com/hyperledger/fabric-cop/cli/server"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
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

func prepEnrollTest() *sqlx.DB {
	if _, err := os.Stat(enrollPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(enrollPath, 0755)
		}
	} else {
		os.RemoveAll(enrollPath)
		os.MkdirAll(enrollPath, 0755)
	}
	return nil
}

// Test the server start command
func TestStartServer(t *testing.T) {
	os.RemoveAll("/tmp/enrollTest")
	rtn := startServer()
	if rtn != 0 {
		t.Errorf("Failed to start server with return code: %d", rtn)
		t.FailNow()
	}
}

func TestEnrollBootstrapUser(t *testing.T) {
	client, err := cutil.NewClient("http://127.0.0.1:8888")
	if err != nil {
		t.Error("Failed to create client")
	}

	req := &idp.EnrollmentRequest{
		Name:   Registrar.User,
		Secret: string(Registrar.Pass),
	}

	ID, err := client.Enroll(req)
	if err != nil {
		t.Log("Error: ", err)
		t.Error("Failed to enroll")
	}
	idByte, err := ID.Serialize()
	if err != nil {
		t.Log("Error: ", err)
	}

	home := util.GetDefaultHomeDir()
	util.WriteFile(home+"/client.json", idByte, 0644)

}

func TestRegister(t *testing.T) {
	rtn := register(REG)
	if rtn != 0 {
		t.Errorf("Failed to register with return code: %d", rtn)
	}

}

func TestRegisterAndEnrollUser(t *testing.T) {
	r := server.NewRegisterUser()
	metaDataBytes, _ := json.Marshal(testEnroll.Attributes)
	metaData := string(metaDataBytes)
	// user.CallerID = Registrar.User
	tok, err := r.RegisterUser(testEnroll.User, testEnroll.Type, testEnroll.Group, metaData, Registrar.User)
	if err != nil {
		t.Errorf("Failed to register user: %s, err: %s", testEnroll.User, err)
	}

	rtn := enroll(testEnroll.User, tok)
	if rtn != 0 {
		t.Errorf("Failed to enroll with return code: %d", rtn)
	}

}

func TestClientCFSSL(t *testing.T) {
	os.Setenv("COP_DEBUG", "true")
	rtn := COPMain([]string{"cop", "cfssl", "version"})
	if rtn != 0 {
		t.Errorf("TestClientCFSSL failed: %d", rtn)
	}
}

func TestBogus(t *testing.T) {
	rtn := COPMain([]string{"cop", "bogus"})
	if rtn == 0 {
		t.Error("TestBogus should have failed but did not")
	}
}

func TestNoArg(t *testing.T) {
	rtn := COPMain([]string{"cop"})
	if rtn == 0 {
		t.Error("TestNoArg should have failed but did not")
	}

	os.RemoveAll(enrollPath)
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
	rtn := COPMain([]string{"cop", "client", "enroll", user, pass, "http://localhost:8888", CSR, "loglevel=0"})
	fmt.Printf("enroll result is '%d'\n", rtn)
	return rtn
}

func register(file string) int {
	fmt.Printf("register file '%s' ...\n", file)
	rtn := COPMain([]string{"cop", "client", "register", file, "http://localhost:8888", "loglevel=0"})
	fmt.Printf("register result is '%d'\n", rtn)
	return rtn
}
