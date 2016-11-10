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

package server

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	factory "github.com/hyperledger/fabric-cop"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

const (
	homeDir    = "/tmp/home"
	dataSource = "/tmp/home/server.db"
	CERT       = "../../testdata/ec.pem"
	KEY        = "../../testdata/ec-key.pem"
	CONFIG     = "../../testdata/testconfig.json"
	DBCONFIG   = "../../testdata/cop-db.json"
	CSR        = "../../testdata/csr.csr"
)

var serverStarted bool
var serverExitCode = 0

func createServer() *Server {
	s := new(Server)
	return s
}

func startServer() int {
	os.RemoveAll(homeDir)
	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		os.Setenv("COP_DEBUG", "true")
		os.Setenv("COP_HOME", homeDir)
		go runServer()
		time.Sleep(5 * time.Second)
		fmt.Println("COP server started")
	} else {
		fmt.Println("COP server already started")
	}
	return serverExitCode
}

func runServer() {
	Start("../../testdata")
}

func TestRegisterUser(t *testing.T) {
	startServer()

	copServer := `{"serverAddr":"http://localhost:8888"}`
	c, _ := factory.NewClient(copServer)

	req := &idp.RegistrationRequest{
		Name: "TestUser1",
		Type: "Client",
	}

	id, _ := factory.NewIdentity()
	identity, err := ioutil.ReadFile("../../testdata/client.json")
	if err != nil {
		t.Error(err)
	}
	util.Unmarshal(identity, id, "identity")

	req.Registrar = id

	c.Register(req)
}

func TestEnrollUser(t *testing.T) {
	copServer := `{"serverAddr":"http://localhost:8888"}`
	c, _ := factory.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	c.Enroll(req)
}

func TestCreateHome(t *testing.T) {
	s := createServer()
	t.Log("Test Creating Home Directory")
	os.Setenv("HOME", "/tmp/test")

	_, err := s.CreateHome()
	if err != nil {
		t.Errorf("Failed to create home directory, error: %s", err)
	}

	if _, err := os.Stat(homeDir); err != nil {
		if os.IsNotExist(err) {
			t.Error("Failed to create home directory")
		}
	}

	os.RemoveAll("/tmp/test")
}

func TestEnroll(t *testing.T) {

	e := NewEnrollUser()
	testUnregisteredUser(e, t)
	testIncorrectToken(e, t)
	testEnrollingUser(e, t)

}

func testUnregisteredUser(e *Enroll, t *testing.T) {
	_, err := e.Enroll("Unregistered", []byte("test"), nil)
	if err == nil {
		t.Error("Unregistered user should not be allowed to enroll, should have failed")
	}
}

func testIncorrectToken(e *Enroll, t *testing.T) {
	_, err := e.Enroll("notadmin", []byte("pass1"), nil)
	if err == nil {
		t.Error("Incorrect token should not be allowed to enroll, should have failed")
	}
}

func testEnrollingUser(e *Enroll, t *testing.T) {
	cr := csr.New()

	csrPEM, _, _ := csr.ParseRequest(cr)

	_, err := e.Enroll("testUser2", []byte("user2"), csrPEM)
	if err != nil {
		t.Error("Failed to enroll user")
	}

	os.RemoveAll(homeDir)
}
