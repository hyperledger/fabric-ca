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
	if _, err := os.Stat(HOME); err != nil {
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
}

func testRegister(c idp.ClientAPI, t *testing.T) {

	identity, err := util.ReadFile("../testdata" + "/client.json")
	if err != nil {
		t.Error(err)
	}
	id := new(Identity)
	err = util.Unmarshal(identity, id, "idp.Identity")
	if err != nil {
		t.Error(err)
	}

	req := &idp.RegistrationRequest{
		Name: "TestUser",
		Type: "Client",
	}

	req.Registrar = id

	c.Register(req)
}

func testRegisterWithoutRegistrar(c idp.ClientAPI, t *testing.T) {

	req := &idp.RegistrationRequest{
		Name: "TestUser",
		Type: "Client",
	}

	id := newIdentity(nil, "test", nil, nil)
	req.Registrar = id

	_, err := c.Register(req)
	if err == nil {
		t.Error("Register should have failed during registration without registrar")
	}
}

func testEnrollIncorrectPassword(c idp.ClientAPI, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "incorrect",
	}

	c.Enroll(req)
}

func testEnroll(c idp.ClientAPI, t *testing.T) {

	req := &idp.EnrollmentRequest{
		Name:   "testUser",
		Secret: "user1",
	}

	c.Enroll(req)
}

func TestDeserializeIdentity(t *testing.T) {
	config := `{"serverAddr":"http://localhost:8888"}`
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

func getClient() idp.ClientAPI {
	copServer := `{"serverAddr":"http://localhost:8888"}`
	c, err := NewClient(copServer)
	if err != nil {
		log.Errorf("Error occured: %s", err)
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
