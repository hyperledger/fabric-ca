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

package lib_test

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
)

var (
	tdDir        = "../testdata"
	fcaDB        = path.Join(tdDir, "fabric-ca-server.db")
	fcaDB2       = path.Join(tdDir, "fabric-ca.db")
	cfgFile      = path.Join(tdDir, "config.json")
	testCfgFile  = "testconfig.json"
	clientConfig = path.Join(tdDir, "client-config.json")
	csrFile      = path.Join(tdDir, "csr.json")
	serversDir   = "testservers"
	adminID      *Identity
)

func TestClient(t *testing.T) {

	server := getServer(7054, path.Join(serversDir, "c1"), "", 1, t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	c := getClient()

	testRegister(c, t)
	testEnrollIncorrectPassword(c, t)
	testDoubleEnroll(c, t)
	testReenroll(c, t)
	testRevocation(c, t, "revoker1", true, true)
	testRevocation(c, t, "nonrevoker1", false, true)
	testRevocation(c, t, "revoker2", true, false)
	testRevocation(c, t, "nonrevoker2", false, false)
	testLoadCSRInfo(c, t)
	testLoadNoCSRInfo(c, t)
	testLoadBadCSRInfo(c, t)

	server.Stop()

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

	err = id.Store()
	if err != nil {
		t.Fatalf("testRegister failed to store admin identity: %s", err)
	}

	adminID = id

	// Register as admin
	registerReq := &api.RegistrationRequest{
		Name:           "MyTestUser",
		Type:           "Client",
		Affiliation:    "hyperledger",
		MaxEnrollments: 1,
	}

	resp, err := id.Register(registerReq)
	if err != nil {
		t.Fatalf("Register failed: %s", err)
	}

	req := &api.EnrollmentRequest{
		Name:   "MyTestUser",
		Secret: resp.Secret,
	}

	id, err = c.Enroll(req)
	if err != nil {
		t.Fatalf("Enroll failed: %s", err)
	}

	if id.GetName() != "MyTestUser" {
		t.Fatal("Incorrect name retrieved")
	}

	if id.GetECert() == nil {
		t.Fatal("No ECert was returned")
	}

	_, err = id.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err != nil {
		t.Fatal("Failed to get batch of TCerts")
	}
}

func testEnrollIncorrectPassword(c *Client, t *testing.T) {

	req := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "incorrect",
	}

	_, err := c.Enroll(req)
	if err == nil {
		t.Error("Enroll with incorrect password passed but should have failed")
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

func testRevocation(c *Client, t *testing.T, user string, withPriv, ecertOnly bool) {
	rr := &api.RegistrationRequest{
		Name:           user,
		Type:           "user",
		Affiliation:    "hyperledger",
		MaxEnrollments: 1,
	}
	if withPriv {
		rr.Attributes = []api.Attribute{api.Attribute{Name: "hf.Revoker", Value: "true"}}
	}
	resp, err := adminID.Register(rr)
	if err != nil {
		t.Fatalf("Failed to register %s", user)
	}
	req := &api.EnrollmentRequest{
		Name:   user,
		Secret: resp.Secret,
	}
	id, err := c.Enroll(req)
	if err != nil {
		t.Errorf("enroll of user '%s' failed", user)
		return
	}
	if ecertOnly {
		err = id.GetECert().RevokeSelf()
	} else {
		err = id.RevokeSelf()
	}
	if withPriv && err != nil {
		t.Errorf("testRevocation failed for user %s: %s", user, err)
	} else if !withPriv && err == nil {
		t.Errorf("testRevocation for user %s passed but should have failed", user)
	}
}

func testLoadCSRInfo(c *Client, t *testing.T) {
	_, err := c.LoadCSRInfo(csrFile)
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
	_, err := c.LoadCSRInfo(cfgFile)
	if err == nil {
		t.Error("testLoadBadCSRInfo passed but should have failed")
	}
}

func TestCustomizableMaxEnroll(t *testing.T) {
	os.Remove("../testdata/fabric-ca-server.db")

	srv := getServer(7055, path.Join(serversDir, "c2"), "", 3, t)
	if srv == nil {
		return
	}

	srv.Config.Registry.MaxEnrollments = 3
	srv.Config.Debug = true

	err := srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	testTooManyEnrollments(t)
	testIncorrectEnrollment(t)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func testTooManyEnrollments(t *testing.T) {
	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("http://localhost:%d", rootPort),
	}

	rawURL := fmt.Sprintf("http://admin:adminpw@localhost:%d", rootPort)

	_, err := clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll: %s", err)
	}

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll: %s", err)
	}

	id, err := clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll: %s", err)
	}

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err == nil {
		t.Errorf("Enroll should have failed, no more enrollments left")
	}

	id.Store()
}

func testIncorrectEnrollment(t *testing.T) {
	c := getTestClient(rootPort)

	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Fatal("Failed to load identity")
	}

	req := &api.RegistrationRequest{
		Name:           "TestUser",
		Type:           "Client",
		Affiliation:    "hyperledger",
		MaxEnrollments: 4,
	}

	_, err = id.Register(req)
	if err == nil {
		t.Error("Registration should have failed, can't register user with max enrollment greater than server max enrollment setting")
	}
}

func TestNormalizeUrl(t *testing.T) {
	_, err := NormalizeURL("")
	if err != nil {
		t.Errorf("NormalizeURL empty: %s", err)
	}
	_, err = NormalizeURL("http://host:7054:x/path")
	if err != nil {
		t.Errorf("NormalizeURL colons: %s", err)
	}
	_, err = NormalizeURL("http://host:7054/path")
	if err != nil {
		t.Errorf("NormalizeURL failed: %s", err)
	}
}

func TestSendBadPost(t *testing.T) {
	c := new(Client)

	c.Config = new(ClientConfig)

	curl := "fake"
	reqBody := []byte("")
	req, _ := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	_, err := c.SendPost(req)
	if err == nil {
		t.Error("Sending post should have failed")
	}
}

func getClient() *Client {
	c, err := NewClient(clientConfig)
	if err != nil {
		log.Errorf("getClient failed: %s", err)
	}
	return c
}

func TestLast(t *testing.T) {
	// Cleanup
	os.Remove("../testdata/cert.pem")
	os.Remove("../testdata/key.pem")
	os.RemoveAll(serversDir)
}
