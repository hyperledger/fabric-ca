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
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	whitePort   = 7058
	rootDir     = "rootDir"
	testdataDir = "../testdata"
	user        = "admin"
	pass        = "adminpw"
	serversDir  = "testservers"
)

var clientConfig = path.Join(testdataDir, "client-config.json")

func TestClient1(t *testing.T) {
	server := getServer(whitePort, path.Join(serversDir, "c1"), "", 1, t)
	if server == nil {
		t.Fatal("Failed to get server")
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}

	testInvalidAuthEnrollment(t)

	server.Stop()

	os.RemoveAll(serversDir)
}

func testInvalidAuthEnrollment(t *testing.T) {
	c := getTestClient(whitePort)
	err := c.Init()
	if err != nil {
		t.Fatalf("Failed to initialize client: %s", err)
	}
	body, err1 := getEnrollmentPayload(t, c)
	if err1 != nil {
		t.Fatalf("Failed to get enrollment payload: %s", err1)
	}

	enrollAndCheck(t, c, body, "Basic admin:adminpw")         // Invalid auth header
	enrollAndCheck(t, c, body, "Basicadmin:adminpw")          // Invalid auth header
	enrollAndCheck(t, c, body, "BasicYWRtaW46YWRtaW5wdw==")   // Invalid auth header
	enrollAndCheck(t, c, body, "Basic YWRtaW46YWRtaW4=")      // Invalid password
	enrollAndCheck(t, c, body, "Basic dXNlcjpwYXNz")          // Invalid user
	enrollAndCheck(t, c, body, "Bearer YWRtaW46YWRtaW5wdw==") // Invalid auth header
	// Invalid auth header, it has to be Basic <base64 encoded user:pass>
	enrollAndCheck(t, c, body, "basic YWRtaW46YWRtaW5wdw==")
	enrollAndCheck(t, c, body, "Basic   YWRtaW46YWRtaW5wdw==")
	enrollAndCheck(t, c, body, "garbage") // Invalid auth header
	enrollAndCheck(t, c, body, "")        // No auth header
}

func enrollAndCheck(t *testing.T, c *Client, body []byte, authHeader string) {
	// Send the CSR to the fabric-ca server with basic auth header
	post, err := c.newPost("enroll", body)
	if err != nil {
		t.Fatalf("Failed to create post request: %s", err)
	}
	if authHeader != "" {
		post.Header.Set("Authorization", authHeader)
	}
	var result enrollmentResponseNet
	err = c.SendReq(post, &result)
	if err != nil {
		t.Logf("err : %v\n", err.Error())
	}
	if err == nil {
		t.Errorf("Enrollment with bad basic auth header '%s' should have failed",
			authHeader)
	}
}

func getEnrollmentPayload(t *testing.T, c *Client) ([]byte, error) {
	req := &api.EnrollmentRequest{
		Name:   user,
		Secret: pass,
	}

	// Generate the CSR
	csrPEM, _, err := c.GenCSR(req.CSR, req.Name)
	if err != nil {
		t.Logf("Enroll failure generating CSR: %s", err)
		return nil, err
	}

	// Get the body of the request
	sreq := signer.SignRequest{
		Request: string(csrPEM),
		Profile: req.Profile,
		Label:   req.Label,
	}

	return util.Marshal(sreq, "SignRequest")
}

func getServer(port int, home, parentURL string, maxEnroll int, t *testing.T) *Server {
	if home != testdataDir {
		os.RemoveAll(home)
	}
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"org2": nil,
	}
	affiliations[affiliationName] = map[string]interface{}{
		"department1": nil,
		"department2": nil,
	}
	srv := &Server{
		Config: &ServerConfig{
			Port:  port,
			Debug: true,
		},
		CA: CA{
			Config: &CAConfig{
				Intermediate: IntermediateCA{
					ParentServer: ParentServer{
						URL: parentURL,
					},
				},
				Affiliations: affiliations,
				Registry: CAConfigRegistry{
					MaxEnrollments: maxEnroll,
				},
			},
		},
		HomeDir: home,
	}
	// The bootstrap user's affiliation is the empty string, which
	// means the user is at the affiliation root
	err := srv.RegisterBootstrapUser(user, pass, "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
		return nil
	}
	return srv
}

func getTestClient(port int) *Client {
	return &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", port)},
		HomeDir: testdataDir,
	}
}
