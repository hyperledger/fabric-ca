/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"strconv"
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
)

const (
	rootPort         = 7055
	rootDir          = "rootDir"
	intermediatePort = 7056
	intermediateDir  = "intDir"
	testdataDir      = "../testdata"
)

func TestServerInit(t *testing.T) {
	server := getRootServer(t)
	if server == nil {
		return
	}
	err := server.Init(false)
	if err != nil {
		t.Errorf("First server init failed")
	}
	err = server.Init(false)
	if err != nil {
		t.Errorf("Second server init failed")
	}
	err = server.Init(true)
	if err != nil {
		t.Errorf("Third Server init renew failed: %s", err)
	}
}

func TestRootServer(t *testing.T) {
	var err error
	var admin, user1 *Identity
	var rr *api.RegistrationResponse
	var recs []CertRecord

	// Start the server
	server := getRootServer(t)
	if server == nil {
		return
	}
	err = server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	defer server.Stop()
	// Enroll request
	client := getRootClient()
	eresp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		t.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	admin = eresp.Identity
	// Register user1
	rr, err = admin.Register(&api.RegistrationRequest{
		Name:        "user1",
		Type:        "user",
		Affiliation: "hyperledger.fabric.security",
	})
	if err != nil {
		t.Fatalf("Failed to register user1: %s", err)
	}
	// Enroll user1
	eresp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: rr.Secret,
	})
	if err != nil {
		t.Fatalf("Failed to enroll user1: %s", err)
	}
	user1 = eresp.Identity
	// The admin ID should have 1 cert in the DB now
	recs, err = server.CertDBAccessor().GetCertificatesByID("admin")
	if err != nil {
		t.Errorf("Could not get admin's certs from DB: %s", err)
	}
	if len(recs) != 1 {
		t.Errorf("Admin should have 1 cert in DB but found %d", len(recs))
	}
	// User1 should not be allowed to register
	_, err = user1.Register(&api.RegistrationRequest{
		Name:        "user2",
		Type:        "user",
		Affiliation: "hyperledger.fabric-ca",
	})
	if err == nil {
		t.Errorf("Failed to register user1: %s", err)
	}
	// User1 renew
	eresp, err = user1.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		t.Fatalf("Failed to reenroll user1: %s", err)
	}
	user1 = eresp.Identity
	// User1 should not be allowed to revoke admin
	err = user1.Revoke(&api.RevocationRequest{Name: "admin"})
	if err == nil {
		t.Error("User1 should not be be allowed to revoke admin")
	}
	// User1 get's batch of tcerts
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err != nil {
		t.Fatalf("Failed to get tcerts for user1: %s", err)
	}
	// Revoke user1's identity
	err = admin.Revoke(&api.RevocationRequest{Name: "user1"})
	if err != nil {
		t.Fatalf("Failed to revoke user1's identity: %s", err)
	}
	// User1 should not be allowed to get tcerts now that it is revoked
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err == nil {
		t.Errorf("User1 should have failed to get tcerts since it is revoked")
	}

	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestIntermediateServer(t *testing.T) {
	var err error

	// Start the root server
	rootServer := getRootServer(t)
	if rootServer == nil {
		return
	}
	err = rootServer.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}
	defer rootServer.Stop()

	for idx := 0; idx < 3; idx++ {
		testIntermediateServer(idx, t)
	}

	// Stop both servers
	err = rootServer.Stop()
	if err != nil {
		t.Errorf("Root server stop failed: %s", err)
	}
}
func TestRunningTLSServer(t *testing.T) {
	srv := getServer(rootPort, testdataDir, "", 0, t)

	srv.Config.TLS.Enabled = true
	srv.Config.TLS.CertFile = "../testdata/tls_server-cert.pem"
	srv.Config.TLS.KeyFile = "../testdata/tls_server-key.pem"

	err := srv.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}

	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("https://localhost:%d", rootPort),
		TLS: tls.ClientTLSConfig{
			CertFilesList: []string{"../testdata/root.pem"},
			Client: tls.KeyCertFiles{
				KeyFile:  "../testdata/tls_client-key.pem",
				CertFile: "../testdata/tls_client-cert.pem",
			},
		},
	}

	rawURL := fmt.Sprintf("https://admin:adminpw@localhost:%d", rootPort)

	_, err = clientConfig.Enroll(rawURL, testdataDir)
	if err != nil {
		t.Errorf("Failed to enroll over TLS: %s", err)
	}

	time.Sleep(1 * time.Second)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestDefaultDatabase(t *testing.T) {
	TestEnd(t)

	srv := getServer(rootPort, testdataDir, "", 0, t)

	err := srv.Start()
	if err != nil {
		t.Fatalf("Root server start failed: %s", err)
	}

	time.Sleep(1 * time.Second)

	err = srv.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

	exist := util.FileExists("../testdata/fabric-ca-server.db")
	if !exist {
		t.Error("Failed to create default sqlite fabric-ca-server.db")
	}
}

func TestBadAuthHeader(t *testing.T) {
	// Start the server
	server := getRootServer(t)
	if server == nil {
		return
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}

	time.Sleep(time.Second)

	invalidTokenAuthorization(t)
	invalidBasicAuthorization(t)

	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}

}

func invalidTokenAuthorization(t *testing.T) {
	client := getRootClient()

	emptyByte := make([]byte, 0)

	req, err := http.NewRequest("POST", "http://localhost:7055/enroll", bytes.NewReader(emptyByte))
	if err != nil {
		t.Error(err)
	}

	CSP := factory.GetDefault()

	cert, err := ioutil.ReadFile("../testdata/ec.pem")
	if err != nil {
		t.Error(err)
	}

	key, err := ioutil.ReadFile("../testdata/ec-key.pem")
	if err != nil {
		t.Error(err)
	}

	token, err := util.CreateToken(CSP, cert, key, emptyByte)
	if err != nil {
		t.Errorf("Failed to add token authorization header: %s", err)
	}

	req.Header.Set("authorization", token)

	err = client.SendReq(req, nil)

	if err.Error() != "Error response from server was: Authorization failure" {
		t.Error("Incorrect auth type set, request should have failed with authorization error")
	}
}

func invalidBasicAuthorization(t *testing.T) {
	client := getRootClient()

	emptyByte := make([]byte, 0)

	req, err := http.NewRequest("POST", "http://localhost:7055/register", bytes.NewReader(emptyByte))
	if err != nil {
		t.Error(err)
	}

	req.SetBasicAuth("admin", "adminpw")

	err = client.SendReq(req, nil)
	if err.Error() != "Error response from server was: Authorization failure" {
		t.Error("Incorrect auth type set, request should have failed with authorization error")
	}
}

func testIntermediateServer(idx int, t *testing.T) {
	// Init the intermediate server
	intermediateServer := getIntermediateServer(idx, t)
	if intermediateServer == nil {
		return
	}
	err := intermediateServer.Init(true)
	if err != nil {
		t.Fatalf("Intermediate server init failed: %s", err)
	}
	// Start it
	err = intermediateServer.Start()
	if err != nil {
		t.Fatalf("Intermediate server start failed: %s", err)
	}
	time.Sleep(time.Second)
	// Stop it
	intermediateServer.Stop()
}

func TestEnd(t *testing.T) {
	os.Remove("../testdata/ca-cert.pem")
	os.Remove("../testdata/ca-key.pem")
	os.Remove("../testdata/fabric-ca-server.db")
	os.RemoveAll(rootDir)
	os.RemoveAll(intermediateDir)
}

func getRootServerURL() string {
	return fmt.Sprintf("http://admin:adminpw@localhost:%d", rootPort)
}

func getRootServer(t *testing.T) *Server {
	return getServer(rootPort, rootDir, "", 0, t)
}

func getIntermediateServer(idx int, t *testing.T) *Server {
	return getServer(
		intermediatePort,
		path.Join(intermediateDir, strconv.Itoa(idx)),
		getRootServerURL(),
		0,
		t)
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
	srv := &Server{
		Config: &ServerConfig{
			Port:         port,
			Debug:        true,
			Affiliations: affiliations,
			Registry: ServerConfigRegistry{
				MaxEnrollments: maxEnroll,
			},
		},
		HomeDir:         home,
		ParentServerURL: parentURL,
	}
	// The bootstrap user's affiliation is the empty string, which
	// means the user is at the affiliation root
	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		t.Errorf("Failed to register bootstrap user: %s", err)
		return nil
	}
	return srv
}

func getRootClient() *Client {
	return getTestClient(rootPort)
}

func getIntermediateClient() *Client {
	return getTestClient(intermediatePort)
}

func getTestClient(port int) *Client {
	return &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", port)},
		HomeDir: testdataDir,
	}
}
