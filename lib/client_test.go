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

package lib

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/cli/server"
)

const (
	ClientTLSConfig = "client-config.json"
	FCADB           = "../testdata/fabric-ca.db"
)

var serverStarted bool
var serverExitCode = 0
var dir string

func TestAllClient(t *testing.T) {
	startServer()

	clientConfig := filepath.Join(dir, ClientTLSConfig)
	os.Link("../testdata/client-config.json", clientConfig)

	c := getClient()

	testRegister(c, t)
	testEnrollIncorrectPassword(c, t)
	testEnroll(c, t)
	testDoubleEnroll(c, t)
	testReenroll(c, t)
	testRevocation(c, t, "revoker", "revokerpw", true, true)
	testRevocation(c, t, "nonrevoker", "nonrevokerpw", true, false)
	testRevocation(c, t, "revoker2", "revokerpw2", false, true)
	testRevocation(c, t, "nonrevoker2", "nonrevokerpw2", false, false)
	testLoadCSRInfo(c, t)
	testLoadNoCSRInfo(c, t)
	testLoadBadCSRInfo(c, t)
}

func testRegister(c *Client, t *testing.T) {

	// Enroll admin
	enrollReq := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	id, err := c.Enroll(enrollReq)
	if err != nil {
		t.Fatalf("testRegister enroll of admin failed: %s", err)
	}

	// Register as admin
	registerReq := &api.RegistrationRequest{
		Name:  "TestUser",
		Type:  "Client",
		Group: "bank_a",
	}

	_, err = id.Register(registerReq)
	if err != nil {
		t.Errorf("Register failed: %s", err)
	}
}

func testEnrollIncorrectPassword(c *Client, t *testing.T) {

	req := &api.EnrollmentRequest{
		Name:   "testUser",
		Secret: "incorrect",
	}

	_, err := c.Enroll(req)
	if err == nil {
		t.Error("Enroll with incorrect password passed but should have failed")
	}
}

func testEnroll(c *Client, t *testing.T) {

	req := &api.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	id, err := c.Enroll(req)
	if err != nil {
		t.Errorf("Enroll failed: %s", err)
	}

	if id.GetName() != "testUser" {
		t.Error("Incorrect name retrieved")
	}

	if id.GetECert() == nil {
		t.Error("No ECert was returned")
	}

	_, err = id.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err != nil {
		t.Errorf("Failed to get batch of TCerts")
	}

	err = id.Store()
	if err != nil {
		t.Errorf("testEnroll: store failed: %s", err)
	}

}

func testDoubleEnroll(c *Client, t *testing.T) {

	req := &api.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	_, err := c.Enroll(req)
	if err == nil {
		t.Error("Double enroll should have failed but passed")
	}

}

func testReenroll(c *Client, t *testing.T) {
	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Errorf("testReenroll: failed LoadMyIdentity: %s", err)
		return
	}
	id, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		t.Errorf("testReenroll: failed reenroll: %s", err)
		return
	}
	err = id.Store()
	if err != nil {
		t.Errorf("testReenroll: failed Store: %s", err)
	}
}

func testRevocation(c *Client, t *testing.T, user, secret string, ecertOnly, shouldPass bool) {
	req := &api.EnrollmentRequest{
		Name:   user,
		Secret: secret,
	}
	id, err := c.Enroll(req)
	if err != nil {
		t.Errorf("enroll of user '%s' with password '%s' failed", user, secret)
		return
	}
	if ecertOnly {
		err = id.GetECert().RevokeSelf()
	} else {
		err = id.RevokeSelf()
	}
	if shouldPass && err != nil {
		t.Errorf("testRevocation failed for user %s: %s", user, err)
	} else if !shouldPass && err == nil {
		t.Errorf("testRevocation for user %s passed but should have failed", user)
	}
}

func testLoadCSRInfo(c *Client, t *testing.T) {
	_, err := c.LoadCSRInfo("../testdata/csr.json")
	if err != nil {
		t.Errorf("testLoadCSRInfo failed: %s", err)
	}
}

func testLoadNoCSRInfo(c *Client, t *testing.T) {
	_, err := c.LoadCSRInfo("nofile")
	if err == nil {
		t.Error("testLoadNoCSRInfo passed but should have failed")
	}
}

func testLoadBadCSRInfo(c *Client, t *testing.T) {
	_, err := c.LoadCSRInfo("../testdata/config.json")
	if err == nil {
		t.Error("testLoadBadCSRInfo passed but should have failed")
	}
}

func TestSendBadPost(t *testing.T) {
	c := new(Client)
	curl := "fake"
	reqBody := []byte("")
	req, _ := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	_, err := c.SendPost(req)
	if err == nil {
		t.Error("Sending post should have failed")
	}
}

func getClient() *Client {
	fcaServer := `{"serverURL":"https://localhost:8888"}`
	c, err := NewClient(fcaServer)
	if err != nil {
		log.Errorf("getClient failed: %s", err)
	}
	return c
}

func startServer() int {
	var err error
	dir, err = ioutil.TempDir("", "lib")
	if err != nil {
		fmt.Printf("Failed to create temp directory [error: %s]", err)
		return serverExitCode
	}

	if !serverStarted {
		os.Remove(FCADB)
		os.RemoveAll(dir)
		serverStarted = true
		fmt.Println("starting fabric-ca server ...")
		go runServer()
		time.Sleep(10 * time.Second)
		fmt.Println("fabric-ca server started")
	} else {
		fmt.Println("fabric-ca server already started")
	}
	return serverExitCode
}

func runServer() {
	os.Setenv("FABRIC_CA_DEBUG", "true")
	os.Setenv("FABRIC_CA_HOME", dir)
	server.Start("../testdata", "testconfig.json")
}

func TestLast(t *testing.T) {
	// Cleanup
	os.Remove(FCADB)
	os.RemoveAll(dir)
}
