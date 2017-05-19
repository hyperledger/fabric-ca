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

	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

var (
	ctport1     = 7098
	ctport2     = 7099
	tdDir       = "../testdata"
	fcaDB       = path.Join(tdDir, "fabric-ca-server.db")
	fcaDB2      = path.Join(tdDir, "fabric-ca.db")
	cfgFile     = path.Join(tdDir, "config.json")
	testCfgFile = "testconfig.json"
	csrFile     = path.Join(tdDir, "csr.json")
	serversDir  = "testservers"
	adminID     *Identity
)

const (
	DefaultCA = ""
)

func TestClient(t *testing.T) {

	server := getServer(ctport1, path.Join(serversDir, "c1"), "", 1, t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	c := getTestClient(ctport1)

	testGetCAInfo(c, t)
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

func testGetCAInfo(c *Client, t *testing.T) {
	req := &api.GetCAInfoRequest{}
	si, err := c.GetCAInfo(req)
	if err != nil {
		t.Fatalf("Failed to get server info: %s", err)
	}
	if si == nil {
		t.Fatal("Server info is nil")
	}
}

func testRegister(c *Client, t *testing.T) {

	// Enroll admin
	enrollReq := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	eresp, err := c.Enroll(enrollReq)
	if err != nil {
		t.Fatalf("testRegister enroll of admin failed: %s", err)
	}

	adminID = eresp.Identity

	err = adminID.Store()
	if err != nil {
		t.Fatalf("testRegister failed to store admin identity: %s", err)
	}

	// Verify that the duration of the newly created enrollment certificate is 1 year
	d, err := util.GetCertificateDurationFromFile(c.GetCertFilePath())
	assert.NoError(t, err)
	assert.True(t, d.Hours() == 8760, fmt.Sprintf("Expecting 8760 but found %f", d.Hours()))

	err = c.CheckEnrollment()
	if err != nil {
		t.Fatalf("testRegister failed to check enrollment: %s", err)
	}

	// Register as admin
	registerReq := &api.RegistrationRequest{
		Name:           "MyTestUser",
		Type:           "Client",
		Affiliation:    "hyperledger",
		MaxEnrollments: 1,
	}

	resp, err := adminID.Register(registerReq)
	if err != nil {
		t.Fatalf("Register failed: %s", err)
	}

	req := &api.EnrollmentRequest{
		Name:   "MyTestUser",
		Secret: resp.Secret,
	}

	eresp, err = c.Enroll(req)
	if err != nil {
		t.Fatalf("Enroll failed: %s", err)
	}
	id := eresp.Identity

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
	eresp, err := id.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		t.Errorf("testReenroll: failed reenroll: %s", err)
		return
	}
	id = eresp.Identity
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
		t.Fatalf("Failed to register %s: %s", user, err)
	}
	req := &api.EnrollmentRequest{
		Name:   user,
		Secret: resp.Secret,
	}
	eresp, err := c.Enroll(req)
	if err != nil {
		t.Errorf("enroll of user '%s' failed", user)
		return
	}
	id := eresp.Identity
	if ecertOnly {
		err = id.GetECert().RevokeSelf()
	} else {
		err = id.RevokeSelf()
	}
	if withPriv && err != nil {
		t.Errorf("testRevocation failed for user %s: %s", user, err)
		return
	} else if !withPriv && err == nil {
		t.Errorf("testRevocation for user %s passed but should have failed", user)
		return
	}

	if withPriv {
		eresp, err = id.Reenroll(&api.ReenrollmentRequest{})
		if err == nil {
			t.Errorf("user ecert %s enrolled but ecert should have been revoked", user)
		}
		if !ecertOnly {
			eresp, err = c.Enroll(req)
			if err == nil {
				t.Errorf("user %s enrolled but should have been revoked", user)
			}
		}
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

	srv := getServer(ctport2, path.Join(serversDir, "c2"), "", 3, t)
	if srv == nil {
		return
	}

	srv.CA.Config.Registry.MaxEnrollments = 3
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
		URL: fmt.Sprintf("http://localhost:%d", ctport2),
	}

	rawURL := fmt.Sprintf("http://admin:adminpw@localhost:%d", ctport2)

	_, err := clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll: %s", err)
	}

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll: %s", err)
	}

	eresp, err := clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll: %s", err)
	}
	id := eresp.Identity

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err == nil {
		t.Errorf("Enroll should have failed, no more enrollments left")
	}

	id.Store()
}

func testIncorrectEnrollment(t *testing.T) {
	c := getTestClient(ctport1)

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
		t.Errorf("normalizeURL empty: %s", err)
	}
	_, err = NormalizeURL("http://host:7054:x/path")
	if err != nil {
		t.Errorf("normalizeURL colons: %s", err)
	}
	_, err = NormalizeURL("http://host:7054/path")
	if err != nil {
		t.Errorf("normalizeURL failed: %s", err)
	}
}

func TestSendBadPost(t *testing.T) {
	c := new(Client)

	c.Config = new(ClientConfig)

	curl := "fake"
	reqBody := []byte("")
	req, _ := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	err := c.SendReq(req, nil)
	if err == nil {
		t.Error("Sending post should have failed")
	}
}

func TestLast(t *testing.T) {
	// Cleanup
	os.RemoveAll("../testdata/msp")
	os.RemoveAll(serversDir)
}
