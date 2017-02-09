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
	"fmt"
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
)

const (
	port = 7055
)

func TestBegin(t *testing.T) {
	clean()
}

func TestServerInit(t *testing.T) {
	server := getServer(t)
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

func TestRunningServer(t *testing.T) {
	var err error
	var admin, user1 *lib.Identity
	var rr *api.RegistrationResponse
	var recs []lib.CertRecord

	// Start the server
	server := getServer(t)
	if server == nil {
		return
	}
	err = server.Start()
	if err != nil {
		t.Fatalf("Server start failed: %s", err)
	}
	// Enroll request
	client := getTestClient()
	admin, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to enroll admin/adminpw: %s", err)
	}
	// Register user1
	rr, err = admin.Register(&api.RegistrationRequest{
		Name:  "user1",
		Type:  "user",
		Group: "hyperledger.fabric.security",
	})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to register user1: %s", err)
	}
	// Enroll user1
	user1, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: rr.Secret,
	})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to enroll user1: %s", err)
	}
	// The admin ID should have 1 cert in the DB now
	recs, err = lib.MyCertDBAccessor.GetCertificatesByID("admin")
	if err != nil {
		t.Errorf("Could not get admin's certs from DB: %s", err)
	}
	if len(recs) != 1 {
		t.Errorf("Admin should have 1 cert in DB but found %d", len(recs))
	}
	// User1 should not be allowed to register
	_, err = user1.Register(&api.RegistrationRequest{
		Name:  "user2",
		Type:  "user",
		Group: "hyperledger.fabric-ca",
	})
	if err == nil {
		t.Errorf("Failed to register user1: %s", err)
	}
	// User1 renew
	user1, err = user1.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		t.Fatalf("Failed to reenroll user1: %s", err)
	}
	// User1 should not be allowed to revoke admin
	err = user1.Revoke(&api.RevocationRequest{Name: "admin"})
	if err == nil {
		t.Error("User1 should not be be allowed to revoke admin")
	}
	// User1 get's batch of tcerts
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to get tcerts for user1: %s", err)
	}
	// Revoke user1's identity
	err = admin.Revoke(&api.RevocationRequest{Name: "user1"})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to revoke user1's identity: %s", err)
	}
	// User1 should not be allowed to get tcerts now that it is revoked
	/* FIXME: The call to revoke.VerifyCertificate in serverauth.go should fail
	_, err = user1.GetTCertBatch(&api.GetTCertBatchRequest{Count: 1})
	if err == nil {
		t.Errorf("User1 should have failed to get tcerts since it is revoked")
	}
	*/
	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestEnd(t *testing.T) {
	clean()
}

func clean() {
	var files = []string{"key.pem", "cert.pem", "ca-key.pem", "ca-cert.pem", "fabric-ca-server.db"}
	for _, file := range files {
		os.Remove(file)
	}
}

func getServer(t *testing.T) *lib.Server {
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"sawtooth": nil,
	}
	srv := &lib.Server{
		Config: &lib.ServerConfig{
			Port:         7055,
			Debug:        true,
			Affiliations: affiliations,
		},
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

func getTestClient() *lib.Client {
	return &lib.Client{
		Config:  &lib.ClientConfig{URL: fmt.Sprintf("http://localhost:%d", port)},
		HomeDir: "../testdata",
	}
}
