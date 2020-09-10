/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package lib

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	cax509 "github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/hyperledger/fabric-ca/lib/common"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	cspsigner "github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/stretchr/testify/assert"
)

const (
	whitePort            = 7058
	username             = "admin"
	pass                 = "adminpw"
	serversDir           = "testservers"
	testTLSClientAuthDir = "testTLSClientAuthDir"
)

var clientConfig = path.Join(testdataDir, "client-config.json")

func TestCWBClient1(t *testing.T) {
	server := getServer(whitePort, path.Join(serversDir, "c1"), "", 1, t)
	if server == nil {
		t.Fatal("Failed to get server")
	}
	err := server.Start()
	if err != nil {
		t.Fatalf("Failed to start server: %s", err)
	}
	defer func() {
		err = server.Stop()
		if err != nil {
			t.Errorf("Server stop failed: %s", err)
		}
		err = os.RemoveAll(serversDir)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()

	testInvalidAuthEnrollment(t)
}

// TestTLS performs 3 main steps:
// 1) Test over HTTP to get an standard ECert
// 2) Test over HTTPS with client auth disabled
// 3) Test over HTTPS with client auth enabled, using standard ECert from #1
func TestCWBTLSClientAuth(t *testing.T) {
	cleanTestSlateCWB(t)
	defer cleanTestSlateCWB(t)
	//
	// 1) Test over HTTP to get a standard ECert
	//
	// Start server
	server := getServer(whitePort, path.Join(testTLSClientAuthDir, "server"), "", 2, t)
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
		Config: &ClientConfig{
			URL: fmt.Sprintf("http://localhost:%d", whitePort),
		},
		HomeDir: path.Join(testTLSClientAuthDir, "client"),
	}

	eresp, err := client.Enroll(&api.EnrollmentRequest{Name: username, Secret: pass})
	if err != nil {
		server.Stop()
		t.Fatalf("Failed to enroll admin: %s", err)
	}
	id := eresp.Identity
	testImpersonation(id, t)
	testMasqueradeEnroll(t, client, id)

	// Register and enroll user to test reenrolling while masquerading
	name := "masqueradeUser2"
	rr, err := id.Register(&api.RegistrationRequest{
		Name:           name,
		Type:           "user",
		Affiliation:    "hyperledger.fabric.security",
		MaxEnrollments: 2,
	})
	if err != nil {
		t.Fatalf("Failed to register maqueradeUser: %s", err)
	}

	eresp2, err := client.Enroll(&api.EnrollmentRequest{Name: name, Secret: rr.Secret})
	if err != nil {
		t.Errorf("Failed to enroll")
	}

	id2 := eresp2.Identity
	testMasqueradeReenroll(t, client, id2)

	// Stop server
	log.Debug("Stopping the server")
	err = server.Stop()
	if err != nil {
		t.Fatalf("Failed to stop server: %s", err)
	}

	//
	// 2) Test over HTTPS with client auth disabled
	//
	// Start server
	log.Debug("Starting the server with TLS")
	server.Config.TLS.Enabled = true
	server.Config.TLS.CertFile = "ca-cert.pem"
	err = server.Start()
	if err != nil {
		t.Fatalf("Failed to start server with HTTPS: %s", err)
	}

	// Close the idle connections that were established to the non-SSL
	// server. client will create new connection for the next request
	// There is no need to do this in real scenario where the Fabric CA
	// server's transport can only be changed from ssl to non-ssl or vice-versa
	// by restarting the server, in which case connections in the client's
	// connection pool are invalidated and it is forced to create new connection.
	client.httpClient.Transport.(*http.Transport).CloseIdleConnections()

	// Try to reenroll over HTTP and it should fail because server is listening on HTTPS
	_, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err == nil {
		t.Error("Client HTTP should have failed to reenroll with server HTTPS")
	}

	client.Config.URL = fmt.Sprintf("https://localhost:%d", whitePort)
	client.Config.TLS.Enabled = true
	client.Config.TLS.CertFiles = []string{"../server/ca-cert.pem"}
	// Reinialize the http client with updated config and re-enroll over HTTPS
	err = client.initHTTPClient()
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
	// Close all idle connections
	client.httpClient.Transport.(*http.Transport).CloseIdleConnections()

	// Try to reenroll and it should fail because client has no client cert
	_, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err == nil {
		t.Error("Client reenroll without client cert should have failed")
	}

	client.Config.TLS.Client.CertFile = path.Join("msp", "signcerts", "cert.pem")
	// Reinialize the http client with updated config and re-enroll over HTTPS with client auth
	err = client.initHTTPClient()
	_, err = id.Reenroll(&api.ReenrollmentRequest{})
	if err != nil {
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
	var result common.EnrollmentResponseNet
	err = c.SendReq(post, &result)
	t.Logf("c.SendReq: %v", err)
	if err == nil {
		t.Errorf("Enrollment with bad basic auth header '%s' should have failed",
			authHeader)
	}
	err = os.RemoveAll("../testdata/msp")
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
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
	var fm os.FileMode = 0777
	os.MkdirAll("msp/keystore", os.FileMode(fm))
	defer func() {
		err = os.RemoveAll("msp")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()

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
	_, err = cax509.NewSigner(privateKey, fakeCertBytes)
	if err == nil {
		t.Fatalf("Should have failed to create signer with fake certificate")
	}
}

func testMasqueradeEnroll(t *testing.T, c *Client, id *Identity) {
	// Register masqueradeUser
	log.Debug("Entering testMasqueradeEnroll")
	name := "masqueradeUser"
	rr, err := id.Register(&api.RegistrationRequest{
		Name:           name,
		Type:           "user",
		Affiliation:    "hyperledger.fabric.security",
		MaxEnrollments: 2,
	})
	if err != nil {
		t.Fatalf("Failed to register maqueradeUser: %s", err)
	}
	// Try to enroll masqueradeUser but masquerading as 'admin'
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

func testMasqueradeReenroll(t *testing.T, c *Client, id *Identity) {
	log.Debug("Entering testMasqueradeReenroll")
	// Try to reenroll but masquerading as 'admin'
	_, err := masqueradeReenroll(c, "admin", id, false, &api.ReenrollmentRequest{})
	if assert.Error(t, err, fmt.Sprintf("%s masquerading as admin (false) should have failed", id.GetName())) {
		assert.Contains(t, err.Error(), "The CSR subject common name must equal the enrollment ID", "Failed for other reason besides masquerading")
	}

	log.Debugf("testMasqueradeEnroll (false) error: %s", err)
	_, err = masqueradeReenroll(c, "admin", id, true, &api.ReenrollmentRequest{})
	if assert.Error(t, err, fmt.Sprintf("%s masquerading as admin (false) should have failed", id.GetName())) {
		assert.Contains(t, err.Error(), "The CSR subject common name must equal the enrollment ID", "Failed for other reason besides masquerading")
	}
	log.Debugf("testMasqueradeEnroll (true) error: %s", err)
}

func getEnrollmentPayload(t *testing.T, c *Client) ([]byte, error) {
	req := &api.EnrollmentRequest{
		Name:   username,
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
		err := os.RemoveAll(home)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}
	srv, err := createServer(port, home, parentURL, maxEnroll)
	if err != nil {
		t.Errorf("failed to register bootstrap user: %s", err)
		return nil
	}
	return srv
}

func getServerForBenchmark(port int, home, parentURL string, maxEnroll int, b *testing.B) *Server {
	if home != testdataDir {
		err := os.RemoveAll(home)
		if err != nil {
			b.Errorf("RemoveAll failed: %s", err)
		}
	}
	srv, err := createServer(port, home, parentURL, maxEnroll)
	if err != nil {
		b.Errorf("failed to register bootstrap user: %s", err)
		return nil
	}
	return srv
}

func createServer(port int, home, parentURL string, maxEnroll int) (*Server, error) {
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
	err := srv.RegisterBootstrapUser(username, pass, "")
	if err != nil {
		return nil, err
	}
	return srv, nil
}

func getTestClient(port int) *Client {
	return &Client{
		Config:  &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", port)},
		HomeDir: testdataDir,
	}
}

func TestCWBCAConfig(t *testing.T) {
	ca := &CA{
		server: &Server{},
	}

	//Error cases
	err := ca.fillCAInfo(nil)
	t.Logf("fillCAInfo err: %v", err)
	if err == nil {
		t.Error("ca.fileCAInfo should have failed but passed")
	}
	_, err = ca.getCAChain()
	t.Logf("getCAChain err: %v", err)
	if err == nil {
		t.Error("getCAChain:1 should have failed but passed")
	}
	ca.Config = &CAConfig{}
	ca.Config.Intermediate.ParentServer.URL = "foo"
	_, err = ca.getCAChain()
	t.Logf("getCAChain err: %v", err)
	if err == nil {
		t.Error("getCAChain:2 should have failed but passed")
	}
	ca.Config.DB.Type = "postgres"
	err = ca.initDB(nil)
	t.Logf("initDB err: %v", err)
	if err == nil {
		t.Error("initDB postgres should have failed but passed")
	}
	ca.Config.DB.Type = "mysql"
	err = ca.initDB(nil)
	t.Logf("initDB err: %v", err)
	if err == nil {
		t.Error("initDB mysql should have failed but passed")
	}

	ca.Config.DB.Type = "unknown"
	err = ca.initDB(nil)
	t.Logf("initDB err: %v", err)
	if err == nil {
		t.Error("initDB unknown should have failed but passed")
	}

	ca.Config.LDAP.Enabled = true
	ca.server = &Server{}
	err = ca.initUserRegistry()
	t.Logf("initUserRegistry err: %v", err)
	if err == nil {
		t.Error("initConfig LDAP passed but should have failed")
	}

	//Non error cases
	err = GenerateECDSATestCert()
	util.FatalError(t, err, "Failed to generate certificate for testing")
	ca.Config.CA.Chainfile = "../testdata/ec.pem"
	_, err = ca.getCAChain()
	t.Logf("getCAChain err: %v", err)
	if err != nil {
		t.Errorf("Failed to getCAChain: %s", err)
	}
	err = ca.initConfig()
	if err != nil {
		t.Errorf("initConfig failed: %s", err)
	}
	ca = &CA{}
	ca.server = &Server{}
	err = ca.initConfig()
	if err != nil {
		t.Errorf("ca.initConfig default failed: %s", err)
	}
	ca.HomeDir = ""
	err = ca.initConfig()
	if err != nil {
		t.Errorf("initConfig failed: %s", err)
	}
	ca.Config = new(CAConfig)
	ca.server = &Server{}
	ca.Config.CA.Certfile = "../testdata/ec_cert.pem"
	ca.Config.CA.Keyfile = "../testdata/ec_key.pem"
	err = ca.initConfig()
	if err != nil {
		t.Errorf("initConfig failed: %s", err)
	}
	s := &Server{}
	s.CA.Config = &CAConfig{}
	err = s.initConfig()
	if err != nil {
		t.Errorf("server.initConfig default failed: %s", err)
	}
}

func TestCWBNewCertificateRequest(t *testing.T) {
	c := &Client{}
	req := &api.CSRInfo{
		Names:      []csr.Name{},
		Hosts:      []string{},
		KeyRequest: api.NewBasicKeyRequest(),
	}
	if c.newCertificateRequest(req, "fake-id") == nil {
		t.Error("newCertificateRequest failed")
	}
}

func TestCWBCAConfigStat(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %s", err)
	}
	td, err := ioutil.TempDir("", "CAConfigStat")
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

	ca := &CA{}
	ca.Config = &CAConfig{}
	ca.HomeDir = "."
	fileInfo, err := os.Stat(".")
	if err != nil {
		t.Fatalf("os.Stat failed on current dir: %s", err)
	}
	oldmode := fileInfo.Mode()
	err = os.Chmod(".", 0000)
	if err != nil {
		t.Fatalf("Chmod on %s failed: %s", fileInfo.Name(), err)
	}
	defer func() {
		err = os.Chmod(td, oldmode)
		if err != nil {
			t.Fatalf("Chmod on %s failed: %s", td, err)
		}
	}()

	ca.Config.DB.Type = ""
	err = ca.initDB(nil)
	t.Logf("initDB err: %v", err)
	if err == nil {
		t.Errorf("initDB should have failed (getcwd failure)")
	}
	ca.Config.DB.Datasource = ""
	ca.HomeDir = ""
}

func cleanTestSlateCWB(t *testing.T) {
	err := os.RemoveAll("msp")
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	err = os.RemoveAll("../testdata/msp")
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	err = os.RemoveAll(serversDir)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	err = os.RemoveAll(testTLSClientAuthDir)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
}

// masqueradeEnroll enrolls a new identity as a masquerader
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
	var result common.EnrollmentResponseNet
	err = c.SendReq(post, &result)
	if err != nil {
		return nil, err
	}
	// Create the enrollment response
	return c.newEnrollmentResponse(&result, req.Name, key)
}

// masqueradeReenroll reenrolls a new identity as a masquerader
func masqueradeReenroll(c *Client, id string, identity *Identity, passInSubject bool, req *api.ReenrollmentRequest) (*EnrollmentResponse, error) {
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
	var result common.EnrollmentResponseNet
	err = identity.Post("reenroll", body, &result, nil)
	if err != nil {
		return nil, err
	}

	// Create the enrollment response
	return c.newEnrollmentResponse(&result, identity.GetName(), key)
}
