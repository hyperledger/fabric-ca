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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/cli/server"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

const (
	CERT     string = "../testdata/ec.pem"
	KEY      string = "../testdata/ec-key.pem"
	CFG      string = "../testdata/cop.json"
	CSR      string = "../testdata/csr.json"
	REG      string = "../testdata/registerrequest.json"
	CONFIG   string = "../../testdata/cop.json"
	DBCONFIG string = "../testdata/enrolltest.json"
	HOME     string = "/tmp/client"
)

var serverStarted bool
var serverExitCode = 0

/* Ash/Pho TODO: commenting out this test until working (Keith)
   Some quick comments:
   1) You can't hardcode URL to localhost in client.go
   2) See the "post" function in client.go
   3) For tests that assume a server is running, the test should go in cop_test.go

import (
	"github.com/hyperledger/fabric-cop/util"
	"testing"
)

func TestGetTCertBatch(t *testing.T) {
	c := NewClient()
	jsonString := util.ConvertJSONFileToJSONString("../../testdata/TCertRequest.json")
	signatureJSON := util.ConvertJSONFileToJSONString("../../testdata/Signature.json")
	//c.GetTCertBatch makes call to COP server to obtain a batch of transaction certificate
	_, err := c.GetTcertBatch(jsonString, signatureJSON)
	if err != nil {
		t.Fatalf("Failed to get tcerts: ", err)
	}
}
*/

func prepTest() {
	_, err := os.Stat(HOME)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(HOME, 0755)
		}
	} else {
		os.RemoveAll(HOME)
		os.MkdirAll(HOME, 0755)
	}
}

func TestAllClient(t *testing.T) {
	prepTest()
	startServer()
	c := getClient()

	testRegister(c, t)
	testRegisterWithoutRegistrar(c, t)
	testEnrollIncorrectPassword(c, t)
	testEnroll(c, t)
	testDoubleEnroll(c, t)
	testReenroll(c, t)
	testLoadCSRInfo(c, t)
	testLoadNoCSRInfo(c, t)
	testLoadBadCSRInfo(c, t)
	testCapabilities(c, t)
}

func testRegister(c *Client, t *testing.T) {

	identity, err := util.ReadFile("../testdata/client.json")
	if err != nil {
		t.Error(err)
	}
	id := new(Identity)
	err = util.Unmarshal(identity, id, "idp.Identity")
	if err != nil {
		t.Error(err)
	}

	req := &idp.RegistrationRequest{
		Name:  "TestUser",
		Type:  "Client",
		Group: "bank_a",
	}

	req.Registrar = id

	_, err2 := c.Register(req)
	if err2 != nil {
		t.Errorf("Register failed: %s", err2)
	}
}

func testRegisterWithoutRegistrar(c *Client, t *testing.T) {

	req := &idp.RegistrationRequest{
		Name: "TestUser",
		Type: "Client",
	}

	_, err := c.Register(req)
	if err == nil {
		t.Error("Register should have failed during registration without registrar")
	}
}

func testEnrollIncorrectPassword(c *Client, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "incorrect",
	}

	_, err := c.Enroll(req)
	if err == nil {
		t.Error("Enroll with incorrect password passed but should have failed")
	}
}

func testEnroll(c *Client, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	id, err := c.Enroll(req)
	if err != nil {
		t.Errorf("Enroll failed: %s", err)
	}

	err = id.Store()
	if err != nil {
		t.Errorf("testEnroll: store failed: %s", err)
	}

}

func testDoubleEnroll(c *Client, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	_, err := c.Enroll(req)
	if err == nil {
		t.Error("Double enroll should have failed but passed")
	}

	msg := err.Error()
	parts := strings.Split(msg, ":")
	if len(parts) < 2 {
		t.Errorf("Invalid error message (%s); only %d parts", msg, len(parts))
	}

	code := parts[0]
	_, err2 := strconv.Atoi(code)
	if err2 != nil {
		t.Errorf("Invalid error message (%s); %s is not an integer; %s", msg, code, err2.Error())
	}

}

func testReenroll(c *Client, t *testing.T) {
	id, err := c.LoadMyIdentity()
	if err != nil {
		t.Errorf("testReenroll: failed LoadMyIdentity: %s", err)
		return
	}
	id, err = c.Reenroll(&idp.ReenrollmentRequest{ID: id})
	if err != nil {
		t.Errorf("testReenroll: failed reenroll: %s", err)
		return
	}
	err = id.Store()
	if err != nil {
		t.Errorf("testReenroll: failed Store: %s", err)
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

func testCapabilities(c *Client, t *testing.T) {
	caps := c.Capabilities()
	if caps == nil {
		t.Error("testCapabilities failed")
	}
}

func TestDeserializeIdentity(t *testing.T) {
	config := `{"serverURL":"http://localhost:8888"}`
	c, err := NewClient(config)
	if err != nil {
		t.Error("Failed to create client object")
	}

	idByte, err := ioutil.ReadFile("../testdata/client.json")
	if err != nil {
		t.Error("Error occured during reading of id file")
	}

	_, err = c.DeserializeIdentity(idByte)
	if err != nil {
		t.Error("Error occured during deserialization, error: ", err)
	}
}

func TestSendBadPost(t *testing.T) {
	c := new(Client)
	curl := "fake"
	reqBody := []byte("")
	req, _ := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	_, err := c.sendPost(req)
	if err == nil {
		t.Error("Sending post should have failed")
	}
}

func getClient() *Client {
	copServer := `{"serverURL":"http://localhost:8888"}`
	c, err := NewClient(copServer)
	if err != nil {
		log.Errorf("getClient failed: %s", err)
	}
	return c
}

func startServer() int {
	if !serverStarted {
		serverStarted = true
		fmt.Println("starting COP server ...")
		os.Setenv("COP_HOME", HOME)
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
	os.Setenv("COP_HOME", HOME)
	server.Start("../testdata")
}
