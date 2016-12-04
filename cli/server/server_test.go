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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	factory "github.com/hyperledger/fabric-cop"
	"github.com/hyperledger/fabric-cop/cli/server/dbutil"
	"github.com/hyperledger/fabric-cop/cli/server/ldap"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/lib"
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
var cfg *Config

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
	cfg = CFG
}

func TestPostgresFail(t *testing.T) {
	_, err := dbutil.GetDB("postgres", "dbname=cop sslmode=disable")
	if err == nil {
		t.Error("No postgres server running, this should have failed")
	}
}

func TestRegisterUser(t *testing.T) {
	startServer()

	copServer := `{"serverURL":"http://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	enrollReq := &idp.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	ID, err := c.Enroll(enrollReq)
	if err != nil {
		t.Error("enroll of user 'admin' with password 'adminpw' failed")
		return
	}

	err = ID.Store()
	if err != nil {
		t.Errorf("Failed to store enrollment information: %s", err)
		return
	}

	regReq := &idp.RegistrationRequest{
		Name:  "TestUser1",
		Type:  "Client",
		Group: "bank_a",
	}

	id, _ := factory.NewIdentity()
	identity, err := ioutil.ReadFile("/tmp/home/client.json")
	if err != nil {
		t.Error(err)
	}
	util.Unmarshal(identity, id, "identity")

	regReq.Registrar = id

	_, err = c.Register(regReq)
	if err != nil {
		t.Error(err)
	}
}

func TestMisc(t *testing.T) {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, err := lib.NewClient(copServer)
	if err != nil {
		t.Errorf("TestMisc.NewClient failed: %s", err)
		return
	}
	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Errorf("TestMisc.LoadMyIdentity failed: %s", err)
		return
	}
	// Test static
	_, err = id.Post("/", nil)
	if err != nil {
		t.Errorf("TestMisc.Static failed: %s", err)
	}
	testStatic(id, t)
	testWithoutAuthHdr(c, t)
}

func TestEnrollUser(t *testing.T) {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	id, err := c.Enroll(req)
	if err != nil {
		t.Error("enroll of user 'testUser' with password 'user1' failed")
		return
	}

	reenrollReq := &idp.ReenrollmentRequest{
		ID: id,
	}

	_, err = c.Reenroll(reenrollReq)
	if err != nil {
		t.Error("reenroll of user 'testUser' failed")
		return
	}

	err = id.RevokeSelf()
	if err == nil {
		t.Error("revoke of user 'testUser' passed but should have failed since has no 'hf.Revoker' attribute")
	}

}

func TestRevoke(t *testing.T) {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "admin2",
		Secret: "adminpw2",
	}

	id, err := c.Enroll(req)
	if err != nil {
		t.Error("enroll of user 'admin2' with password 'adminpw2' failed")
		return
	}

	err = id.Revoke(&idp.RevocationRequest{})
	if err == nil {
		t.Error("Revoke with no args should have failed but did not")
	}

	err = id.Revoke(&idp.RevocationRequest{Serial: "foo", AKI: "bar"})
	if err == nil {
		t.Error("Revoke with bogus serial and AKI should have failed but did not")
	}

	err = id.Revoke(&idp.RevocationRequest{Name: "foo"})
	if err == nil {
		t.Error("Revoke with bogus name should have failed but did not")
	}

	err = id.RevokeSelf()
	if err != nil {
		t.Error("revoke of user 'admin2' failed")
		return
	}

	err = id.RevokeSelf()
	if err == nil {
		t.Error("RevokeSelf twice should have failed but did not")
	}
}

func TestMaxEnrollment(t *testing.T) {
	CFG.UsrReg.MaxEnrollments = 2

	copServer := `{"serverURL":"http://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	regReq := &idp.RegistrationRequest{
		Name:  "MaxTestUser",
		Type:  "Client",
		Group: "bank_a",
	}

	id, _ := factory.NewIdentity()
	identity, err := ioutil.ReadFile("/tmp/home/client.json")
	if err != nil {
		t.Error(err)
	}
	util.Unmarshal(identity, id, "identity")

	regReq.Registrar = id

	resp, err := c.Register(regReq)
	if err != nil {
		t.Error(err)
	}

	secretBytes, err := base64.StdEncoding.DecodeString(resp.Secret)

	enrollReq := &idp.EnrollmentRequest{
		Name:   "MaxTestUser",
		Secret: string(secretBytes),
	}

	_, err = c.Enroll(enrollReq)
	if err != nil {
		t.Error("Enroll of user 'MaxTestUser' failed")
		return
	}

	_, err = c.Enroll(enrollReq)
	if err != nil {
		t.Error("Enroll of user 'MaxTestUser' failed")
		return
	}

	_, err = c.Enroll(enrollReq)
	if err == nil {
		t.Error("Enroll of user should have failed, max enrollment reached")
		return
	}

}

func TestCreateHome(t *testing.T) {
	s := createServer()
	t.Log("Test Creating Home Directory")
	os.Unsetenv("COP_HOME")
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

}

func TestEnroll(t *testing.T) {
	e := NewEnrollUser()

	testUnregisteredUser(e, t)
	testIncorrectToken(e, t)
	testEnrollingUser(e, t)
}

func testUnregisteredUser(e *Enroll, t *testing.T) {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "Unregistered",
		Secret: "test",
	}

	_, err := c.Enroll(req)

	if err == nil {
		t.Error("Unregistered user should not be allowed to enroll, should have failed")
	}
}

func testIncorrectToken(e *Enroll, t *testing.T) {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "notadmin",
		Secret: "pass1",
	}

	_, err := c.Enroll(req)

	if err == nil {
		t.Error("Incorrect token should not be allowed to enroll, should have failed")
	}
}

func testEnrollingUser(e *Enroll, t *testing.T) {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, _ := lib.NewClient(copServer)

	req := &idp.EnrollmentRequest{
		Name:   "testUser2",
		Secret: "user2",
	}

	_, err := c.Enroll(req)

	if err != nil {
		t.Error("Enroll of user 'testUser2' with password 'user2' failed")
		return
	}

}

func TestGetCertificatesByID(t *testing.T) {
	certRecord, err := certDBAccessor.GetCertificatesByID("testUser2")
	if err != nil {
		t.Errorf("Error occured while getting certificate for id 'testUser2', [error: %s]", err)
	}
	if len(certRecord) == 0 {
		t.Error("Failed to get certificate by user id, for user: 'testUser2'")
	}
}

func TestRevokeCertificatesByID(t *testing.T) {
	_, err := certDBAccessor.RevokeCertificatesByID("testUser2", 1)
	if err != nil {
		t.Errorf("Error occured while revoking certificate for id 'testUser2', [error: %s]", err)
	}
}

func TestGetField(t *testing.T) {
	_, err := userRegistry.GetField("testUser2", 5)
	if err == nil {
		t.Errorf("Error should occured while getting unsupported field, [error: %s]", err)
	}
}

func TestUpdateField(t *testing.T) {
	err := userRegistry.UpdateField("testUser2", state, 5)
	if err != nil {
		t.Errorf("Error occured while updating state field for id 'testUser2', [error: %s]", err)
	}
}

func TestUserRegistry(t *testing.T) {

	err := InitUserRegistry(&Config{DBdriver: "postgres", DataSource: "dbname=cop sslmode=disable"})
	if err == nil {
		t.Error("Trying to create a postgres registry should have failed")
	}

	err = InitUserRegistry(&Config{DBdriver: "mysql", DataSource: "root:root@tcp(localhost:3306)/cop?parseTime=true"})
	if err == nil {
		t.Error("Trying to create a mysql registry should have failed")
	}

	err = InitUserRegistry(&Config{DBdriver: "foo", DataSource: "boo"})
	if err == nil {
		t.Error("Trying to create a unsupported database type should have failed")
	}

	err = InitUserRegistry(&Config{LDAP: &ldap.Config{}})
	if err == nil {
		t.Error("Trying to LDAP with no URL; it should have failed but passed")
	}

}

func TestLast(t *testing.T) {
	// Cleanup
	os.RemoveAll(homeDir)
}

func testStatic(id *lib.Identity, t *testing.T) {
	_, err := id.Post("/", nil)
	if err != nil {
		t.Errorf("testStatic failed: %s", err)
	}
}

func testWithoutAuthHdr(c *lib.Client, t *testing.T) {
	req, err := c.NewPost("enroll", nil)
	if err != nil {
		t.Errorf("testWithAuthHdr.NewPost failed: %s", err)
		return
	}
	_, err = c.SendPost(req)
	if err == nil {
		t.Error("testWithAuthHdr.SendPost should have failed but passed")
	}
}
