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
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	cspsigner "github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/utils"
)

const (
	whitePort            = 7058
	user                 = "admin"
	pass                 = "adminpw"
	serversDir           = "testservers"
	testTLSClientAuthDir = "testTLSClientAuthDir"
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

// TestTLS performs 3 main steps:
// 1) Test over HTTP to get an standard ecert
// 2) Test over HTTPS with client auth disabled
// 3) Test over HTTPS with client auth enabled, using standard ecert from #1
func TestTLSClientAuth(t *testing.T) {
	os.RemoveAll(testTLSClientAuthDir)
	defer os.RemoveAll(testTLSClientAuthDir)
	//
	// 1) Test over HTTP to get a standard ecert
	//
	// Start server
	server := getServer(whitePort, path.Join(testTLSClientAuthDir, "server"), "", 1, t)
	if server == nil {
		return
	}
	server.CA.Config.CSR.CN = "localhost"
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}
	// Enroll over HTTP
	client := &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", whitePort)},
		HomeDir: path.Join(testTLSClientAuthDir, "client"),
	}
	eresp, err := client.Enroll(&api.EnrollmentRequest{Name: user, Secret: pass})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to enroll admin: %s", err)
	}
	id := eresp.Identity
	testImpersonation(id, t)
	testMasqueradeEnroll(t, client, id)
	// Stop server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Failed to stop server: %s", err)
	}

	//
	// 2) Test over HTTPS with client auth disabled
	//
	// Start server
	server.Config.TLS.Enabled = true
	server.Config.TLS.CertFile = "ca-cert.pem"
	err = server.Start()
	if err != nil {
		t.Fatalf("Failed to start server with HTTPS: %s", err)
	}
	// Try to reenroll over HTTP and it should fail because server is listening on HTTPS
	_, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err == nil {
		t.Error("Client HTTP should have failed to reenroll with server HTTPS")
	}
	// Reenroll over HTTPS
	client.Config.URL = fmt.Sprintf("https://localhost:%d", whitePort)
	client.Config.TLS.Enabled = true
	client.Config.TLS.CertFiles = []string{"../server/ca-cert.pem"}
	resp, err := id.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to reenroll over HTTPS: %s", err)
	}
	id = resp.Identity
	// Store identity persistently
	err = id.Store()
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to store identity: %s", err)
	}
	// Stop server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Failed to stop server: %s", err)
	}

	//
	// 3) Test over HTTPS with client auth enabled
	//
	server.Config.TLS.ClientAuth.Type = "RequireAndVerifyClientCert"
	server.Config.TLS.ClientAuth.CertFiles = []string{"ca-cert.pem"}
	err = server.Start()
	if err != nil {
		t.Fatalf("Failed to start server with HTTPS and client auth: %s", err)
	}
	// Try to reenroll and it should fail because client has no client cert
	_, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err == nil {
		t.Error("Client reenroll without client cert should have failed")
	}
	// Reenroll over HTTPS with client auth
	client.Config.TLS.Client.CertFile = path.Join("msp", "signcerts", "cert.pem")
	_, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
		server.Stop()
		t.Errorf("Client reenroll with client auth failed: %s", err)
	}
	// Stop server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Failed to stop server: %s", err)
	}
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

// Try to impersonate 'id' identity by creating a self-signed certificate
// with the same serial and AKI as this identity.
func testImpersonation(id *Identity, t *testing.T) {
	// test as a fake user trying to impersonate admin give only the cert
	cert, err := BytesToX509Cert(id.GetECert().Cert())
	if err != nil {
		t.Fatalf("Failed to convert admin's cert: %s", err)
	}
	bc := &factory.FactoryOpts{}
	csp, err := util.InitBCCSP(&bc, "", path.Join(testTLSClientAuthDir, "client"))
	if err != nil {
		t.Fatalf("Failed to initialize BCCSP: %s", err)
	}
	privateKey, err := csp.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	cspSigner, err := cspsigner.New(csp, privateKey)
	if err != nil {
		t.Fatalf("Failed initializing signer: %s", err)
	}
	// Export the public key
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA public key: %s", err)
	}
	pkRaw, err := publicKey.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}
	pub, err := utils.DERToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to ECDSA.PublicKey [%s]", err)
	}
	fakeCertBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, cspSigner)
	if err != nil {
		t.Fatalf("Failed to create self-signed fake cert: %s", err)
	}
	fakeCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeCertBytes})
	fakeID := newIdentity(id.GetClient(), "admin", privateKey, fakeCert)
	err = fakeID.RevokeSelf()
	if err == nil {
		t.Fatalf("Fake ID should not have failed revocation")
	}
}

func testMasqueradeEnroll(t *testing.T, c *Client, id *Identity) {
	// Register masqueradeUser
	log.Debug("Entering testMasqueradeEnroll")
	name := "masqueradeUser"
	rr, err := id.Register(&api.RegistrationRequest{
		Name:        name,
		Type:        "user",
		Affiliation: "hyperledger.fabric.security",
	})
	if err != nil {
		t.Fatalf("Failed to register maqueradeUser: %s", err)
	}
	// Try to enroll user1 but masquerading as 'admin'
	_, err = masqueradeEnroll(c, "admin", false, &api.EnrollmentRequest{
		Name:   name,
		Secret: rr.Secret,
	})
	if err == nil {
		t.Fatalf("%s masquerading as admin (false) should have failed", name)
	}
	log.Debugf("testMasqueradeEnroll (false) error: %s", err)
	_, err = masqueradeEnroll(c, "admin", true, &api.EnrollmentRequest{
		Name:   name,
		Secret: rr.Secret,
	})
	if err == nil {
		t.Fatalf("%s masquerading as admin (true) should have failed", name)
	}
	log.Debugf("testMasqueradeEnroll (true) error: %s", err)
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

// Enroll enrolls a new identity
// @param req The enrollment request
func masqueradeEnroll(c *Client, id string, passInSubject bool, req *api.EnrollmentRequest) (*EnrollmentResponse, error) {
	err := c.Init()
	if err != nil {
		return nil, err
	}
	csrPEM, key, err := c.GenCSR(req.CSR, id)
	if err != nil {
		log.Debugf("Enroll failure generating CSR: %s", err)
		return nil, err
	}
	reqNet := &api.EnrollmentRequestNet{
		CAName: req.CAName,
	}
	if req.CSR != nil {
		reqNet.SignRequest.Hosts = req.CSR.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = req.Profile
	reqNet.SignRequest.Label = req.Label
	if passInSubject {
		reqNet.SignRequest.Subject = &signer.Subject{CN: id}
	}
	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}
	// Send the CSR to the fabric-ca server with basic auth header
	post, err := c.newPost("enroll", body)
	if err != nil {
		return nil, err
	}
	post.SetBasicAuth(req.Name, req.Secret)
	var result enrollmentResponseNet
	err = c.SendReq(post, &result)
	if err != nil {
		return nil, err
	}
	// Create the enrollment response
	return c.newEnrollmentResponse(&result, req.Name, key)
}
