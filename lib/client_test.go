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
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/common/attrmgr"
	"github.com/stretchr/testify/assert"
)

var (
	ctport1     = 7098
	ctport2     = 7099
	intCAPort   = 7080
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

func TestCLIClientConfigStat(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %s", err)
	}
	td, err := ioutil.TempDir("", "ClientConfigStat")
	if err != nil {
		t.Fatalf("failed to get tmp dir: %s", err)
	}
	defer func() {
		err = os.RemoveAll(td)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()
	err = os.Chdir(td)
	if err != nil {
		t.Fatalf("failed to cd to %v: %s", td, err)
	}
	defer func() {
		err = os.Chdir(wd)
		if err != nil {
			t.Fatalf("failed to cd to %v: %s", wd, err)
		}
	}()
	fileInfo, err := os.Stat(".")
	if err != nil {
		t.Fatalf("os.Stat failed on current dir: %s", err)
	}
	oldmode := fileInfo.Mode()
	err = os.Chmod(".", 0000)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", td, err)
	}
	defer func() {
		err = os.Chmod(td, oldmode)
		if err != nil {
			t.Fatalf("Chmod on %s failed: %s", td, err)
		}
	}()
	c := new(Client)
	c.Config = new(ClientConfig)
	err = c.Init()
	t.Logf("initDB err: %v", err)
	if err == nil {
		t.Errorf("initDB should have failed (getcwd failure)")
	}
}

func TestCLIClientInit(t *testing.T) {
	client := new(Client)
	client.Config = new(ClientConfig)
	client.Config.MSPDir = string(make([]byte, 1))
	err := client.Init()
	t.Logf("Client Init() error %v", err)
	if err == nil {
		t.Errorf("Init should have failed to create keystoreDir")
	}
	defer func() {
		err = os.RemoveAll(filepath.Join(os.TempDir(), "signcerts"))
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll(filepath.Join(os.TempDir(), "cacerts"))
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll(filepath.Join(os.TempDir(), "keystore"))
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()

	client.Config.MSPDir = strings.Repeat("a", 260)
	err = client.CheckEnrollment()
	t.Logf("Client CheckEnrollment() error %v", err)
	if err == nil {
		t.Errorf("CheckEnrollment should have failed: %s", err)
	}
	client.Config.MSPDir = os.TempDir()
	_, err = os.Create(filepath.Join(os.TempDir(), "signcerts"))
	if err != nil {
		t.Fatalf("Failed to create cert file: %s", err)
	}
	err = client.Init()
	t.Logf("Client Init() error %v", err)
	if err == nil {
		t.Fatalf("Init should have failed to create certDir")
	}
	err = os.Rename(filepath.Join(os.TempDir(), "signcerts"), filepath.Join(os.TempDir(), "cacerts"))
	if err != nil {
		t.Fatalf("Failed to rename cert dir: %s", err)
	}
	err = client.Init()
	t.Logf("Client Init() error %v", err)
	if err == nil {
		t.Errorf("Init should have failed to create cacertsDir")
	}
}

func TestCLIClient(t *testing.T) {
	server := TestGetServer(ctport1, path.Join(serversDir, "c1"), "", 1, t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}
	stopserver := true
	defer func() {
		if stopserver {
			err = server.Stop()
			if err != nil {
				t.Errorf("Failed to stop server: %s", err)
			}
		}
		err = os.RemoveAll(serversDir)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("msp")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("../testdata/msp")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()

	c := getTestClient(ctport1)

	testLoadIdentity(c, t)
	testGetCAInfo(c, t)
	testRegister(c, t)
	testEnrollIncorrectPassword(c, t)
	testDoubleEnroll(c, t)
	testReenroll(c, t)
	testRevocation(c, t, "revoker1", true, true)
	testRevocation(c, t, "nonrevoker1", false, true)
	testRevocation(c, t, "revoker2", true, false)
	testRevocation(c, t, "nonrevoker2", false, false)
	testRevocationErrors(c, t)
	testLoadCSRInfo(c, t)
	testLoadNoCSRInfo(c, t)
	testLoadBadCSRInfo(c, t)
	testEnrollMiscFailures(c, t)

	stopserver = false
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

	testWhenServerIsDown(c, t)
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

	client2 := new(Client)
	client2.Config = new(ClientConfig)
	client2.Config.MSPDir = string(make([]byte, 1))
	_, err = client2.GetCAInfo(req)
	if err == nil {
		t.Errorf("Should have failed to get server info")
	}

	client2.Config.MSPDir = ""
	client2.Config.URL = "http://localhost:["
	_, err = client2.GetCAInfo(req)
	if err == nil {
		t.Errorf("Should have failed due to invalid URL")
	}

	client2.Config.MSPDir = ""
	client2.Config.URL = ""
	client2.Config.TLS.Enabled = true
	_, err = client2.GetCAInfo(req)
	if err == nil {
		t.Errorf("Should have failed due to invalid TLS config")
	}
}

func testRegister(c *Client, t *testing.T) {

	// Enroll admin
	enrollReq := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	err := c.CheckEnrollment()
	if err == nil {
		t.Fatalf("testRegister check enrollment should have failed - client not enrolled")
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
	if assert.NoError(t, err) {
		assert.True(t, int(d.Hours()) == 8760, "Expecting 8760 but found %f", d.Hours())
	}

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

	// Test registration and enrollment of an identity with attributes
	userName := "MyTestUserWithAttrs"
	registerReq = &api.RegistrationRequest{
		Name:        userName,
		Type:        "client",
		Affiliation: "hyperledger",
		Attributes: []api.Attribute{
			api.Attribute{Name: "attr1", Value: "val1", ECert: true},
			api.Attribute{Name: "attr2", Value: "val2"},
		},
	}
	resp, err = adminID.Register(registerReq)
	if err != nil {
		t.Fatalf("Register of %s failed: %s", userName, err)
	}

	// Get an ECert with no explict attribute requested and make sure we get the defaults.
	req = &api.EnrollmentRequest{
		Name:   userName,
		Secret: resp.Secret,
	}
	eresp, err = c.Enroll(req)
	if err != nil {
		t.Fatalf("Enroll with attributes failed: %s", err)
	}
	// Verify that the ECert has the correct attributes.
	attrs, err := eresp.Identity.GetECert().Attributes()
	if err != nil {
		t.Fatalf("%s", err)
	}
	checkAttrResult(t, "hf.EnrollmentID", userName, attrs)
	checkAttrResult(t, "hf.Type", "client", attrs)
	checkAttrResult(t, "hf.Affiliation", "hyperledger", attrs)
	checkAttrResult(t, "attr1", "val1", attrs)
	checkAttrResult(t, "attr2", "", attrs)

	// Another test of registration and enrollment of an identity with attributes
	userName = "MyTestUserWithAttrs2"
	registerReq = &api.RegistrationRequest{
		Name:        userName,
		Type:        "client",
		Affiliation: "hyperledger",
		Attributes: []api.Attribute{
			api.Attribute{Name: "attr1", Value: "val1", ECert: true},
			api.Attribute{Name: "attr2", Value: "val2"},
		},
	}
	resp, err = adminID.Register(registerReq)
	if err != nil {
		t.Fatalf("Register of %s failed: %s", userName, err)
	}

	// Request an ECert with hf.EnrollmentID, hf.Type, hf.Affiliation, attr1 but without attr2.
	req = &api.EnrollmentRequest{
		Name:   userName,
		Secret: resp.Secret,
		AttrReqs: []*api.AttributeRequest{
			&api.AttributeRequest{Name: "hf.Type"},
			&api.AttributeRequest{Name: "hf.Affiliation"},
			&api.AttributeRequest{Name: "attr1"},
		},
	}
	eresp, err = c.Enroll(req)
	if err != nil {
		t.Fatalf("Enroll with attributes failed: %s", err)
	}
	// Verify that the ECert has the correct attributes
	attrs, err = eresp.Identity.GetECert().Attributes()
	if err != nil {
		t.Fatalf("%s", err)
	}
	checkAttrResult(t, "hf.EnrollmentID", "", attrs)
	checkAttrResult(t, "hf.Type", "client", attrs)
	checkAttrResult(t, "hf.Affiliation", "hyperledger", attrs)
	checkAttrResult(t, "attr1", "val1", attrs)
	checkAttrResult(t, "attr2", "", attrs)

	// Request an ECert with an attribute that the identity does not have (attr3)
	// but we say that it is required.  This should result in an error.
	req = &api.EnrollmentRequest{
		Name:   userName,
		Secret: resp.Secret,
		AttrReqs: []*api.AttributeRequest{
			&api.AttributeRequest{Name: "attr1", Optional: true},
			&api.AttributeRequest{Name: "attr3"},
		},
	}
	eresp, err = c.Enroll(req)
	if err == nil {
		t.Fatalf("Enroll should have failed because %s does not have attr3", userName)
	}

	// Register a user with no attributes.
	userName = "MyTestUserWithNoAttrs"
	registerReq = &api.RegistrationRequest{
		Name:        userName,
		Type:        "client",
		Affiliation: "hyperledger",
	}
	resp, err = adminID.Register(registerReq)
	if err != nil {
		t.Fatalf("Register of %s failed: %s", userName, err)
	}
	// Try to enroll the user with no attributes with the "ca" profile.
	// Since the identity doesn't have the "hf.IntermediateCA" attribute,
	// this should fail.
	req = &api.EnrollmentRequest{
		Name:    userName,
		Secret:  resp.Secret,
		Profile: "ca",
	}
	_, err = c.Enroll(req)
	if err == nil {
		t.Fatalf("Enroll to 'ca' profile should have failed because %s does not have the hf.IntermediateCA attribute", userName)
	}

}

func checkAttrResult(t *testing.T, name, val string, attrs *attrmgr.Attributes) {
	v, ok, err := attrs.Value(name)
	if assert.NoError(t, err) {
		if val == "" {
			assert.False(t, ok, "attribute '%s' was found", name)
		} else if assert.True(t, ok, "attribute '%s' was not found", name) {
			assert.True(t, v == val, "invalid value of attribute '%s'; expecting '%s' but found '%s'", name, val, v)
		}
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

func testEnrollMiscFailures(c *Client, t *testing.T) {
	req := &api.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	c.Config.URL = "http://localhost:["
	_, err := c.Enroll(req)
	t.Logf("Client Enroll error %v", err)
	if err == nil {
		t.Error("Enroll should have failed due to URL error")
	}

	c.Config.URL = ""
	var r api.CSRInfo
	var k api.BasicKeyRequest
	var n csr.Name
	k.Algo = "dsa"
	k.Size = 256
	n.C = "US"

	r.KeyRequest = &k
	r.Names = []csr.Name{n}
	r.Hosts = []string{"host"}
	r.KeyRequest = &k
	req.CSR = &r
	_, err = c.Enroll(req)
	t.Logf("Client Enroll error %v", err)
	if err == nil {
		t.Error("Enroll should have failed due to invalid CSR algo")
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
	var revResp *api.RevocationResponse
	if ecertOnly {
		revResp, err = id.GetECert().RevokeSelf()
	} else {
		revResp, err = id.RevokeSelf()
	}
	if withPriv {
		// Assert that there is no error revoking user/Ecert
		ar := assert.NoError(t, err, "Revocation failed for user %s", user)
		if !ar {
			return
		}

		// Assert that the cert serial in the revocation response is same as that of user certificate
		cert, err := id.GetECert().GetX509Cert()
		if err != nil {
			t.Fatalf("Failed to get certificate for the enrolled user %s: %s", user, err)
		}
		assert.Equal(t, 1, len(revResp.RevokedCerts), "Expected 1 certificate to be revoked")
		assert.Equal(t, util.GetSerialAsHex(cert.SerialNumber), revResp.RevokedCerts[0].Serial,
			"Cert serial in revocation response does match serial number of the cert that was revoked")

		eresp, err = id.Reenroll(&api.ReenrollmentRequest{})
		assert.Errorf(t, err, "Enrollment of a revoked user %s cert succeeded but should have failed", user)
		if !ecertOnly {
			eresp, err = c.Enroll(req)
			assert.Errorf(t, err, "Enrollment of a revoked user %s succeeded but should have failed", user)
		}
	} else {
		assert.Errorf(t, err, "Revocation for user %s should have failed", user)
	}
}

func testRevocationErrors(c *Client, t *testing.T) {
	var revoker = "erroneous_revoker"
	var revoker2 = "erroneous_revoker2"
	var user = "etuser"

	// register and enroll revoker
	rr := &api.RegistrationRequest{
		Name:           revoker,
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: 1,
		Attributes:     []api.Attribute{api.Attribute{Name: "hf.Revoker", Value: "true"}},
	}
	resp, err := adminID.Register(rr)
	if err != nil {
		t.Fatalf("Failed to register %s %s", revoker, err)
	}
	req := &api.EnrollmentRequest{
		Name:   revoker,
		Secret: resp.Secret,
	}
	eresp, err := c.Enroll(req)
	if err != nil {
		t.Errorf("enroll of user %s failed", revoker)
		return
	}
	revokerId := eresp.Identity

	// register and enroll revoker2
	rr = &api.RegistrationRequest{
		Name:           revoker2,
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: 1,
		Attributes:     []api.Attribute{api.Attribute{Name: "hf.Revoker", Value: "faux"}},
	}
	_, err = adminID.Register(rr)
	assert.Error(t, err, "Invalid value 'faux' provided for a boolean type attribute")
	// register and enroll revoker2
	rr = &api.RegistrationRequest{
		Name:           revoker2,
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: 1,
		Attributes:     []api.Attribute{api.Attribute{Name: "hf.Revoker", Value: "false"}},
	}
	resp, err = adminID.Register(rr)
	if err != nil {
		t.Fatalf("Failed to register %s %s", revoker2, err)
	}
	req = &api.EnrollmentRequest{
		Name:   revoker2,
		Secret: resp.Secret,
	}
	eresp, err = c.Enroll(req)
	if err != nil {
		t.Errorf("enroll of user %s failed", revoker2)
		return
	}
	revoker2Id := eresp.Identity

	// register and enroll test user
	rr = &api.RegistrationRequest{
		Name:           user,
		Type:           "user",
		Affiliation:    "hyperledger",
		MaxEnrollments: 1,
		Attributes:     []api.Attribute{api.Attribute{}},
	}
	resp, err = adminID.Register(rr)
	if err != nil {
		t.Fatalf("Failed to register %s: %s", user, err)
	}
	req = &api.EnrollmentRequest{
		Name:   user,
		Secret: resp.Secret,
	}
	eresp, err = c.Enroll(req)
	if err != nil {
		t.Errorf("enroll of user '%s' failed: %v", user, err)
		return
	}

	// Revoke cert that doesn't exist
	user = "etuser"
	revreq := &api.RevocationRequest{
		Name:   user,
		Serial: "1",
		AKI:    "1",
		Reason: "privilegeWithdrawn",
	}

	id := eresp.Identity
	_, err = revokerId.Revoke(revreq)
	t.Logf("testRevocationErrors revoke error %v", err)
	if err == nil {
		t.Errorf("Revocation should have failed")
	}
	_, err = revoker2Id.Revoke(revreq)
	t.Logf("testRevocationErrors revoke error %v", err)
	if err == nil {
		t.Errorf("Revocation should have failed")
	}
	eresp, err = id.Reenroll(&api.ReenrollmentRequest{})
	t.Logf("testRevocationErrors reenroll error %v", err)
	if err != nil {
		t.Errorf("%s renroll failed and ecert should not be revoked", user)
	}

	// Revoke cert that exists, but doesn't belong to user
	revreq.Name = "fake"
	revreq.Serial, revreq.AKI, err = GetCertID(eresp.Identity.GetECert().Cert())
	t.Logf("Name: %s, Serial: %s, AKI: %s. err, %v", revreq.Name, revreq.Serial, revreq.AKI, err)
	_, err = revokerId.Revoke(revreq)
	t.Logf("testRevocationErrors revoke error %v", err)
	if err == nil {
		t.Errorf("Revocation should have failed")
	}
	eresp, err = id.Reenroll(&api.ReenrollmentRequest{})
	t.Logf("testRevocationErrors reenroll error %v", err)
	if err != nil {
		t.Errorf("%s renroll failed and ecert should not be revoked", user)
	}

	// Cannot revoke across affiliations
	revreq.Name = "etuser"
	revreq.Serial, revreq.AKI, err = GetCertID(eresp.Identity.GetECert().Cert())
	t.Logf("Name: %s, Serial: %s, AKI: %s. err, %v", revreq.Name, revreq.Serial, revreq.AKI, err)
	_, err = revokerId.Revoke(revreq)
	t.Logf("testRevocationErrors revoke error %v", err)
	if err == nil {
		t.Errorf("Revocation should have failed")
	}
	eresp, err = id.Reenroll(&api.ReenrollmentRequest{})
	t.Logf("testRevocationErrors reenroll error %v", err)
	if err != nil {
		t.Errorf("%s renroll failed and ecert should not be revoked", user)
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

func testLoadIdentity(c *Client, t *testing.T) {
	_, err := c.LoadIdentity("foo", "bar")
	if err == nil {
		t.Error("testLoadIdentity foo/bar passed but should have failed")
	}
	_, err = c.LoadIdentity("foo", "../testdata/ec.pem")
	if err == nil {
		t.Error("testLoadIdentity foo passed but should have failed")
	}
	_, err = c.LoadIdentity("../testdata/ec-key.pem", "../testdata/ec.pem")
	if err != nil {
		t.Errorf("testLoadIdentity failed: %s", err)
	}
}

func TestCLICustomizableMaxEnroll(t *testing.T) {
	srv := TestGetServer(ctport2, path.Join(serversDir, "c2"), "", 3, t)
	if srv == nil {
		return
	}

	srv.CA.Config.Registry.MaxEnrollments = 3
	srv.Config.Debug = true

	err := srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}
	defer func() {
		err = os.RemoveAll("../testdata/fabric-ca-server.db")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll(serversDir)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("../testdata/msp")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()

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
		t.Fatalf("Failed to load identity: %s", err)
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

// Test cases for gencrl command
func TestGenCRL(t *testing.T) {
	t.Log("Testing genCRL")

	serverHome := path.Join(serversDir, "gencrlserver")
	clientHome := path.Join(tdDir, "gencrlclient")
	err := os.RemoveAll(serverHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s", serverHome)
	}
	err = os.RemoveAll(clientHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s", clientHome)
	}
	defer os.RemoveAll(serverHome)
	defer os.RemoveAll(clientHome)

	srv, adminID := setupGenCRLTest(t, serverHome, clientHome)
	defer func() {
		if srv != nil {
			srv.Stop()
		}
	}()

	_, err = adminID.GenCRL(&api.GenCRLRequest{CAName: ""})
	assert.NoError(t, err, "failed to generate CRL")

	// error cases
	// Error case 1: revokedafter is greater than revokedbefore
	gencrlReq := &api.GenCRLRequest{
		CAName:        "",
		RevokedBefore: time.Now().UTC().AddDate(0, 1, 0),
		RevokedAfter:  time.Now().UTC().AddDate(0, 2, 0),
	}
	_, err = adminID.GenCRL(gencrlReq)
	assert.Error(t, err, "genCRL should have failed as revokedafter timestamp is after revokedbefore timestamp")
	assert.Contains(t, err.Error(), "Invalid 'revokedafter' value", "Not expected error message")

	// Error case 2: expireafter is greater than expirebefore
	gencrlReq = &api.GenCRLRequest{
		CAName:       "",
		ExpireBefore: time.Now().UTC().AddDate(0, 1, 0),
		ExpireAfter:  time.Now().UTC().AddDate(0, 2, 0),
	}
	_, err = adminID.GenCRL(gencrlReq)
	assert.Error(t, err, "genCRL should have failed as expireafter timestamp is after expirebefore timestamp")
	assert.Contains(t, err.Error(), "Invalid 'expireafter' value", "Not expected error message")

	// Error case 3: gencrl request by an user without hf.GenCRL authority should fail
	gencrluser := "gencrluser1"
	rr := &api.RegistrationRequest{
		Name:           gencrluser,
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: 1,
	}
	resp, err := adminID.Register(rr)
	if err != nil {
		t.Fatalf("Failed to register %s: %s", gencrluser, err)
	}

	eresp, err := adminID.GetClient().Enroll(&api.EnrollmentRequest{
		Name:   gencrluser,
		Secret: resp.Secret,
	})
	if err != nil {
		t.Fatalf("Failed to enroll user %s: %s", gencrluser, err)
	}

	user1 := eresp.Identity
	_, err = user1.GenCRL(gencrlReq)
	assert.Error(t, err, "genCRL should have failed as invoker does not have hf.GenCRL attribute")
}

func TestGenCRLWithIntServer(t *testing.T) {
	t.Log("Testing genCRL against intermediate CA server")

	rootCAHome := path.Join(serversDir, "gencrlrootserver")
	intCAHome := path.Join(serversDir, "gencrlintserver")
	clientHome := path.Join(tdDir, "gencrlclient")
	err := os.RemoveAll(rootCAHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s", rootCAHome)
	}
	err = os.RemoveAll(intCAHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s", intCAHome)
	}
	err = os.RemoveAll(clientHome)
	if err != nil {
		t.Fatalf("Failed to remove directory %s", clientHome)
	}

	removeDirs := func() {
		os.RemoveAll(rootCAHome)
		os.RemoveAll(intCAHome)
		os.RemoveAll(clientHome)
	}
	defer removeDirs()

	rootCASrv, intCASrv, adminID := setupGenCRLWithIntServerTest(t, rootCAHome, intCAHome, clientHome, false)
	stopServers := func() {
		if rootCASrv != nil {
			rootCASrv.Stop()
		}
		if intCASrv != nil {
			intCASrv.Stop()
		}
	}
	defer stopServers()

	_, err = adminID.GenCRL(&api.GenCRLRequest{CAName: ""})
	assert.NoError(t, err, "failed to generate CRL")

	stopServers()
	removeDirs()

	// Error case: Do not give 'crl sign' usage to the intermediate CA certificate and try generating a CRL
	// It should return an error
	rootCASrv, intCASrv, adminID = setupGenCRLWithIntServerTest(t, rootCAHome, intCAHome, clientHome, true)
	_, err = adminID.GenCRL(&api.GenCRLRequest{CAName: ""})
	assert.Error(t, err, "gen CRL should have failed because intermediate CA does not have 'crl sign' usage")
}

func setupGenCRLWithIntServerTest(t *testing.T, rootCAHome, intCAHome, clientHome string, noCrlSign bool) (*Server, *Server, *Identity) {
	// Start the root CA server
	rootCASrv := TestGetServer(ctport1, rootCAHome, "", 1, t)
	if rootCASrv == nil {
		t.Fatalf("Failed to get server")
	}
	// If noCrlSign is true, remove 'crl sign' usage from the ca profile
	if noCrlSign {
		caProfile := rootCASrv.CA.Config.Signing.Profiles["ca"]
		caProfile.Usage = caProfile.Usage[0:1]
	}
	err := rootCASrv.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	// Start the intermediate CA server
	intCASrv := TestGetServer(intCAPort, intCAHome,
		fmt.Sprintf("http://admin:adminpw@localhost:%d", ctport1),
		-1, t)
	if intCASrv == nil {
		t.Fatalf("Failed to get server")
	}

	d, _ := time.ParseDuration("2h")
	intCASrv.CA.Config.Signing.Default.Expiry = d

	err = intCASrv.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	// Enroll admin
	c := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", intCAPort)},
		HomeDir: clientHome,
	}
	eresp, err := c.Enroll(&api.EnrollmentRequest{Name: "admin", Secret: "adminpw"})
	if err != nil {
		t.Fatalf("Failed to enroll admin: %s", err)
	}
	adminID := eresp.Identity

	// Register and revoker a user using admin identity
	user := "gencrluser"
	rr := &api.RegistrationRequest{
		Name:           user,
		Type:           "user",
		Affiliation:    "hyperledger",
		MaxEnrollments: 1,
	}
	resp, err := adminID.Register(rr)
	if err != nil {
		t.Fatalf("Failed to register user '%s': %s", user, err)
	}
	req := &api.EnrollmentRequest{
		Name:   user,
		Secret: resp.Secret,
	}
	eresp, err = c.Enroll(req)
	if err != nil {
		t.Fatalf("Failed to enroll user '%s': %s", user, err)
	}
	_, err = adminID.Revoke(&api.RevocationRequest{Name: user})
	if err != nil {
		t.Fatalf("Failed to revoke user '%s': %s", user, err)
	}
	return rootCASrv, intCASrv, adminID
}

func setupGenCRLTest(t *testing.T, serverHome, clientHome string) (*Server, *Identity) {
	server := TestGetServer(ctport1, serverHome, "", 1, t)
	if server == nil {
		t.Fatalf("Failed to get server")
	}
	d, _ := time.ParseDuration("2h")
	server.CA.Config.Signing.Default.Expiry = d

	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	c := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", ctport1)},
		HomeDir: clientHome,
	}

	// Enroll admin
	eresp, err := c.Enroll(&api.EnrollmentRequest{Name: "admin", Secret: "adminpw"})
	if err != nil {
		t.Fatalf("Failed to enroll admin: %s", err)
	}
	adminID := eresp.Identity

	// Register and revoker a user
	user := "gencrluser"
	rr := &api.RegistrationRequest{
		Name:           user,
		Type:           "user",
		Affiliation:    "hyperledger",
		MaxEnrollments: 1,
	}
	resp, err := adminID.Register(rr)
	if err != nil {
		t.Fatalf("Failed to register user '%s': %s", user, err)
	}
	req := &api.EnrollmentRequest{
		Name:   user,
		Secret: resp.Secret,
	}
	eresp, err = c.Enroll(req)
	if err != nil {
		t.Fatalf("Failed to enroll user '%s': %s", user, err)
	}
	_, err = adminID.Revoke(&api.RevocationRequest{Name: user})
	if err != nil {
		t.Fatalf("Failed to revoke user '%s': %s", user, err)
	}
	return server, adminID
}

func TestCLINormalizeUrl(t *testing.T) {
	u, err := NormalizeURL("")
	if err != nil {
		t.Errorf("normalizeURL empty: %s", err)
	} else {
		t.Logf("URL %s, %s, %s", u.Scheme, u.Host, u.Path)
	}
	u, err = NormalizeURL("http://host:7054:x/path")
	if err != nil {
		t.Errorf("normalizeURL colons: %s", err)
	} else {
		t.Logf("URL %s, %s, %s", u.Scheme, u.Host, u.Path)
	}
	u, err = NormalizeURL("http://host:7054/path")
	if err != nil {
		t.Errorf("normalizeURL failed: %s", err)
	} else {
		t.Logf("URL %s, %s, %s", u.Scheme, u.Host, u.Path)
	}
	u, err = NormalizeURL("https://localhost:80/a%2Fb%2Fc")
	if err != nil {
		t.Errorf("NormalizeURL failed: %s", err)
	} else {
		t.Logf("URL %s, %s, %s", u.Scheme, u.Host, u.Path)
	}
	_, err = NormalizeURL("[")
	t.Logf("NormalizeURL() error %v", err)
	if err == nil {
		t.Errorf("NormalizeURL '[' should have failed")
	}
	_, err = NormalizeURL("http://[/path")
	t.Logf("NormalizeURL() error %v", err)
	if err == nil {
		t.Errorf("NormalizeURL 'http://[/path]' should have failed")
	}
	_, err = NormalizeURL("https:rootless/path")
	t.Logf("NormalizeURL() error %v", err)
	if err == nil {
		t.Errorf("NormalizeURL 'https:rootless/path' should have failed")
	}
}

func TestCLISendBadPost(t *testing.T) {
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

// Test to make sure that CSR is generated by GenCSR function
func TestCLIGenCSR(t *testing.T) {
	config := new(ClientConfig)

	homeDir := filepath.Join(testdataDir, "identity")

	defer func() {
		err := os.RemoveAll(homeDir)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()

	config.CSR.CN = "identity"
	err := config.GenCSR(homeDir)
	if err != nil {
		t.Fatalf("Failed to generate CSR: %s", err)
	}
	csrFile := filepath.Join(homeDir, "msp", "signcerts", "identity.csr")
	_, err = os.Stat(csrFile)
	if os.IsNotExist(err) {
		t.Fatalf("CSR file does not exist at %s", csrFile)
	}
	err = os.RemoveAll(homeDir)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}

	// Error cases
	//CN is missing
	config.CSR.CN = ""
	err = config.GenCSR(homeDir)
	if err == nil {
		t.Fatalf("GenCSR should fail as CN is missing: %s", err)
	}

	// Fail to write file
	config.CSR.CN = strings.Repeat("a", 260)
	err = config.GenCSR(homeDir)
	t.Logf("ClientConfig.GenCSR error %v", err)
	if err == nil {
		t.Error("ClientConfig.GenCSR should have failed due to invalid filename")
	}

	// Fail to gen key
	config.CSR = api.CSRInfo{
		CN: "TestGenCSR",
		KeyRequest: &api.BasicKeyRequest{
			Algo: "dsa",
			Size: 256,
		},
	}
	err = config.GenCSR(homeDir)
	t.Logf("ClientConfig.GenCSR error %v", err)
	if err == nil {
		t.Error("ClientConfig.GenCSR should have failed due to unsupported algorithm")
	}

	// Fail to init client
	config.MSPDir = string(make([]byte, 1))
	err = config.GenCSR(homeDir)
	t.Logf("ClientConfig.GenCSR error %v", err)
	if err == nil {
		t.Error("ClientConfig.GenCSR should have failed to init client")
	}

}

// Test to make sure that once an identity is revoked, all subsequent commands
// invoked by revoked user should be rejected by server for all its issued certificates
func TestRevokedIdentity(t *testing.T) {
	serverdir := filepath.Join(testdataDir, "server")

	srv := TestGetServer(ctport1, serverdir, "", -1, t)
	err := srv.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}
	defer func() {
		err := srv.Stop()
		if err != nil {
			t.Errorf("Server stop failed: %s", err)
		}
		err = os.RemoveAll(serverdir)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("client")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()

	// Enroll admin
	c := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", ctport1)},
		HomeDir: "client/admin",
	}

	enrollReq := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	eresp, err := c.Enroll(enrollReq)
	if err != nil {
		t.Fatalf("Enrollment of admin failed: %s", err)
	}

	admin_id := eresp.Identity

	// 'admin' registers 'TestUser' user
	registerReq := &api.RegistrationRequest{
		Name:           "TestUser",
		Type:           "user",
		Affiliation:    "hyperledger",
		MaxEnrollments: 2,
	}

	resp, err := admin_id.Register(registerReq)
	if err != nil {
		t.Fatalf("Register failed: %s", err)
	}

	// Enroll 'TestUser'
	TestUserClient := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", ctport1)},
		HomeDir: "client/TestUserClient",
	}

	enrollReq = &api.EnrollmentRequest{
		Name:   "TestUser",
		Secret: resp.Secret,
	}

	eresp2, err := TestUserClient.Enroll(enrollReq)
	if err != nil {
		t.Fatalf("Enrollment of TestUser failed: %s", err)
	}

	testuserid := eresp2.Identity

	// Enroll 'TestUser' again with a different home/msp directory
	TestUserClient2 := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", ctport1)},
		HomeDir: "client/TestUserClient2",
	}

	enrollReq = &api.EnrollmentRequest{
		Name:   "TestUser",
		Secret: resp.Secret,
	}

	eresp3, err := TestUserClient2.Enroll(enrollReq)
	if err != nil {
		t.Fatalf("Enrollment of TestUser failed: %s", err)
	}

	testuserid2 := eresp3.Identity

	// 'admin' revokes user 'TestUser'
	revReq := &api.RevocationRequest{
		Name: "TestUser",
	}

	_, err = admin_id.Revoke(revReq)
	if err != nil {
		t.Fatalf("Failed to revoke TestUser identity: %s", err)
	}

	// After an identity has been revoked, all subsequent commands invoked by revoked user should be rejected by server
	// for all its issued certificates
	_, err = TestUserClient2.Enroll(enrollReq)
	if err == nil {
		t.Fatalf("Enrollment of TestUser should have failed: %s", err)
	}

	_, err = testuserid.Reenroll(&api.ReenrollmentRequest{})
	if err == nil {
		t.Fatalf("Reenrollment of TestUser identity should have failed: %s", err)
	}

	_, err = testuserid2.Reenroll(&api.ReenrollmentRequest{})
	if err == nil {
		t.Fatalf("Reenrollment of TestUser identity should have failed: %s", err)
	}

	_, err = testuserid.Register(registerReq)
	if err == nil {
		t.Fatalf("Registeration of TestUser identity should have failed: %s", err)
	}

	_, err = testuserid2.Register(registerReq)
	if err == nil {
		t.Fatalf("Registeration of TestUser identity should have failed: %s", err)
	}

	_, err = testuserid.Revoke(&api.RevocationRequest{
		Name: "admin",
	})
	if err == nil {
		t.Fatalf("Revocation of 'admin' identity should have failed: %s", err)
	}

	_, err = testuserid2.Revoke(&api.RevocationRequest{
		Name: "admin",
	})
	if err == nil {
		t.Fatalf("Revocation of 'admin' identity should have failed: %s", err)
	}

	c = new(Client)
	c.Config = new(ClientConfig)
	c.Config.URL = fmt.Sprintf("http://localhost:%d", ctport1)

	// Bad TLS
	c.Config.MSPDir = "msp"
	var kc tls.KeyCertFiles
	kc.KeyFile = "../testdata/ec_key.pem"
	kc.CertFile = "../testdata/expiredcert.pem"
	c.Config.MSPDir = ""
	c.Config.URL = ""
	c.Config.TLS.Enabled = true
	c.Config.TLS.CertFiles = []string{"../testdata/ec.pem"}
	c.Config.TLS.Client = kc
	curl := fmt.Sprintf("http://localhost:%d/api/v1/register", ctport1)
	reqBody := []byte("")
	req, _ := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	err = c.SendReq(req, nil)
	t.Logf("Client SendReq() error %v", err)
	if err == nil {
		t.Error("Sending post with bad TLS config should have failed")
	}

	err = GenerateECDSATestCert()
	util.FatalError(t, err, "Failed to generate certificate for testing")
	kc.CertFile = "../testdata/ec_cert.pem"
	c.Config.TLS.Client = kc
	req, _ = http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	err = c.SendReq(req, nil)
	t.Logf("Client SendReq() error %v", err)
	if err == nil {
		t.Error("Sending post with bad TLS config should have failed")
	}

	// Bad URL
	curl = fmt.Sprintf("http://localhost:%d/fake", ctport1)
	reqBody = []byte("")
	req, _ = http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	err = c.SendReq(req, nil)
	t.Logf("Client SendReq() error %v", err)
	if err == nil {
		t.Error("Sending post with bad URL should have failed")
	}

	// No authorization header
	curl = fmt.Sprintf("http://localhost:%d/api/v1/revoke", ctport1)
	reqBody = []byte("")
	req, _ = http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	err = c.SendReq(req, nil)
	t.Logf("Client SendReq() error %v", err)
	if err == nil {
		t.Error("Sending register with no authorization header should have failed")
	}

	// Bad authorization header
	curl = fmt.Sprintf("http://localhost:%d/api/v1/register", ctport1)
	reqBody = []byte("")
	req, _ = http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	req.Header.Add("Authorization", "bad-auth")
	err = c.SendReq(req, nil)
	t.Logf("Client SendReq() error %v", err)
	if err == nil {
		t.Error("Sending register with bad authorization header should have failed")
	}

	// Bad Init
	c2 := new(Client)
	c2.Config = new(ClientConfig)
	c2.Config.URL = fmt.Sprintf("http://localhost:%d", ctport1)
	c2.Config.MSPDir = string(make([]byte, 1))
	curl = fmt.Sprintf("http://localhost:%d/api/v1/register", ctport1)
	reqBody = []byte("")
	req, _ = http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	err = c2.SendReq(req, nil)
	t.Logf("Client SendReq() error %v", err)
	if err == nil {
		t.Error("Sending post with bad Init should have failed")
	}
}

func testWhenServerIsDown(c *Client, t *testing.T) {
	enrollReq := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}
	_, err := c.Enroll(enrollReq)
	if err == nil {
		t.Error("Enroll while server is down should have failed")
	}
	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Fatalf("LoadMyIdentity failed: %s", err)
	}
	_, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err == nil {
		t.Error("Reenroll while server is down should have failed")
	}
	registration := &api.RegistrationRequest{
		Name:        "TestUser",
		Type:        "Client",
		Affiliation: "hyperledger",
	}
	_, err = id.Register(registration)
	if err == nil {
		t.Error("Register while server is down should have failed")
	}
	_, err = id.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err == nil {
		t.Error("GetTCertBatch while server is down should have failed")
	}
}
