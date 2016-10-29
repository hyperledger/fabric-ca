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

package defaultImpl

import (
	"bytes"
	"fmt"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/util"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Client is the default implementation of COP client
type Client struct {
	certFile, keyFile string
	user, pass, home  string
	serverAddr        string
	cfg               cli.Config
}

// NewClient creates a new client
func NewClient() *Client {
	c := new(Client)
	c.home = getDefaultHomeDir()
	return c
}

//GetTcertBatch returns a batch of tcerts
func (c *Client) GetTcertBatch(jsonString string, signatureJSON string) (string, error) {
	ECsignature := util.SignECMessage(jsonString, signatureJSON)

	v := url.Values{}
	v.Set("Tcertjson", jsonString)
	v.Add("signature", ECsignature)

	resp, err := http.PostForm("http://localhost:8888/api/v1/cfssl/gettcertbatch", v)
	if err != nil {
		log.Fatal("Error making call to COP server to get tcert")
	}
	response, _ := ioutil.ReadAll(resp.Body)

	//TODO: process the response
   /*
	var output map[string]interface{}

	err = json.Unmarshal([]byte(string(response)), &output)
	if err != nil {
			log.Fatal("Error unmarshalling response:", err)
	}
   */
	return string(response), nil
}

// GetHomeDir returns the client's home directory
func (c *Client) GetHomeDir() string {
	return c.home
}

// SetHomeDir sets the home directory
func (c *Client) SetHomeDir(home string) {
	c.home = home
}

// GetServerAddr returns the server address
func (c *Client) GetServerAddr() string {
	return c.serverAddr
}

// SetServerAddr sets the server address
func (c *Client) SetServerAddr(addr string) {
	c.serverAddr = addr
}

// SetConfig initializes by JSON config
func (c *Client) SetConfig(json string) cop.Error {
	// TODO: implement
	return nil
}

// Register a new identity
func (c *Client) Register(req *cop.RegisterRequest) cop.Error {
	log.Debugf("Register %+v", req)
	// Send a post to the "register" endpoint with req as body
	_, err := c.post("register", req)
	if err != nil {
		log.Debugf("Register error: %+v", err)
		return err
	}
	log.Debug("Register success")
	return nil
}

// IsEnrolled returns true if the client is already enrolled
func (c *Client) IsEnrolled() bool {
	return util.FileExists(c.getMyCertPath())
}

// Enroll a registered identity
func (c *Client) Enroll(req *cop.EnrollRequest, csrJSON string) ([]byte, cop.Error) {
	log.Debugf("Enrolling %s to %s", req.User, c.serverAddr)
	fmt.Println("client.go - Enroll")

	if c.serverAddr == "" {
		fmt.Println("client.go - serverAddr")
		log.Debug("server address not set")
		return nil, cop.NewError(cop.ServerAddrNotSet, "failed enrolling %s' because server address was not set", req.User)
	}
	fmt.Println("Enroll - HERE")

	if c.IsEnrolled() {
		log.Debugf("%s is already enrolled", req.User)
		return c.getMyCert()
	}

	fmt.Println("Enroll - HERE 1")

	csrPEM, err := c.genCSR(csrJSON)
	if err != nil {
		return nil, err
	}

	req.CSR = csrPEM

	cert, err := c.post("enroll", req)
	if err != nil {
		log.Debugf("enroll error: %+v", err)
		return nil, err
	}
	log.Debug("enroll success")

	c.putMyCert(cert)

	// c.user = id
	// c.pass = secret

	return cert, nil
}

// RegisterAndEnroll registers and enrolls a new identity
func (c *Client) RegisterAndEnroll(registration *cop.RegisterRequest) (cop.Identity, cop.Error) {
	// TODO: implement
	return nil, nil
}

// SubmitJoinRequest submits a join request, implicitly approving by the caller
// Returns the join request ID
func (c *Client) SubmitJoinRequest(participantFile string) (*cop.JoinRequest, cop.Error) {
	// TODO: implement
	return nil, nil
}

// ApproveJoinRequest approves the join request
func (c *Client) ApproveJoinRequest(joinRequestID string) cop.Error {
	// TODO: implement
	return nil
}

// DenyJoinRequest denies the join request
func (c *Client) DenyJoinRequest(joinRequestID string) cop.Error {
	// TODO: implement
	return nil
}

// ListJoinRequests lists the currently outstanding join requests for the blockchain network
func (c *Client) ListJoinRequests() ([]cop.JoinRequest, cop.Error) {
	// TODO: implement
	return nil, nil
}

// ListParticipants lists the current participants in the blockchain network
func (c *Client) ListParticipants() ([]string, cop.Error) {
	// TODO: implement
	return nil, nil
}

// SetJoinRequestListener sets the listener to be called when a JoinRequestEvent is emitted
func (c *Client) SetJoinRequestListener(listener cop.JoinRequestListener) {
	// TODO: implement
}

// Add the basic auth header
func (c *Client) addBasicAuthHdr(req *http.Request, body []byte) {
	log.Debug("addBasicAuthHdr")
	req.SetBasicAuth(c.user, c.pass)
}

// Add the token auth header
func (c *Client) addTokenAuthHdr(req *http.Request, body []byte) cop.Error {
	log.Debug("addTokenAuthHdr begin")
	cert, err := c.getMyCert()
	if err != nil {
		log.Debug("addTokenAuthHdr failed: getMyCert")
		return err
	}
	key, err := c.getMyKey()
	if err != nil {
		log.Debug("addTokenAuthHdr failed: getMyKey")
		return err
	}
	token, tokenerr := util.CreateToken(cert, key, body)
	if tokenerr != nil {
		log.Debug("addTokenAuthHdr failed: CreateToken")
		return cop.WrapError(tokenerr, 1, "test")
	}
	req.Header.Set("authorization", token)
	log.Debug("addTokenAuthHdr success")
	return nil
}

func (c *Client) genCSR(csrFile string) ([]byte, cop.Error) {
	log.Debugf("genCSR %s", csrFile)
	fmt.Println("genCSR")
	csrFileBytes, err := util.ReadFile(csrFile)
	if err != nil {
		return nil, err
	}

	req := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}
	err = util.Unmarshal(csrFileBytes, &req, "CSR file")
	if err != nil {
		return nil, err
	}

	fmt.Println("HERE in gencsr")
	var key, csrPEM []byte
	g := &csr.Generator{Validator: Validator}
	csrPEM, key, rerr := g.ProcessRequest(&req)
	if rerr != nil {
		key = nil
		log.Errorf("processRequest error: %s", err)
		return nil, cop.WrapError(rerr, cop.CFSSL, "failed in CSR generator")
	}

	c.putMyKey(key)

	log.Debug("genCSR success")
	fmt.Println("genCSR success")
	return csrPEM, nil

}

// Validator does nothing and will never return an error. It exists because creating a
// csr.Generator requires a Validator.
func Validator(req *csr.CertificateRequest) error {
	return nil
}

// // func signerMain(args []string, c cli.Config) ([]byte, error) {
// func (c *Client) signKey(csrPEM []byte, remoteHost string) ([]byte, cop.Error) {
// 	log.Debugf("signKey remoteHost=%s", remoteHost)
// 	c.cfg.Remote = remoteHost
// 	s, err := sign.SignerFromConfig(c.cfg)
// 	if err != nil {
// 		log.Errorf("SignerFromConfig error: %s", err)
// 		return nil, cop.WrapError(err, cop.CFSSL, "failed in SignerFromConfig")
// 	}
// 	req := signer.SignRequest{
// 		// Hosts:   signer.SplitHosts(c.Hostname),
// 		Request: string(csrPEM),
// 		// Profile: c.Profile,
// 		// Label:   c.Label,
// 	}
// 	s.SetReqModifier(c.addBasicAuthHdr)
// 	cert, err := s.Sign(req)
// 	if err != nil {
// 		log.Errorf("Sign error: %s", err)
// 		return nil, cop.WrapError(err, cop.CFSSL, "failed in Sign")
// 	}
// 	c.putMyCert(cert)
// 	log.Debug("Sign success")
// 	return cert, nil
// }

func (c *Client) getMyKey() (key []byte, err cop.Error) {
	return util.ReadFile(c.getMyKeyPath())
}

func (c *Client) putMyKey(key []byte) cop.Error {
	return util.WriteFile(c.getMyKeyPath(), key, 0700)
}

func (c *Client) getMyCert() (key []byte, err cop.Error) {
	return util.ReadFile(c.getMyCertPath())
}

func (c *Client) putMyCert(cert []byte) cop.Error {
	return util.WriteFile(c.getMyCertPath(), cert, 0755)
}

func (c *Client) getMyKeyPath() string {
	return c.getMyFilePath("client-key.pem")
}

func (c *Client) getMyCertPath() string {
	return c.getMyFilePath("client-cert.pem")
}

func (c *Client) getMyFilePath(file string) string {
	os.MkdirAll(c.home, 0755)
	return filepath.Join(c.home, file)
}

// Send a POST to the COP server and get a response
func (c *Client) post(endpoint string, reqBody interface{}) (respBody []byte, cerr cop.Error) {
	log.Debugf("posting to %s: %+v", endpoint, reqBody)
	fmt.Println("post")
	reqBodyBytes, cerr := util.Marshal(reqBody, endpoint)
	if cerr != nil {
		return nil, cerr
	}
	curl, cerr := c.getURL(endpoint)
	if cerr != nil {
		return nil, cerr
	}
	req, err := http.NewRequest("POST", curl, bytes.NewReader(reqBodyBytes))
	if err != nil {
		msg := fmt.Sprintf("failed to create new request to %s: %v", curl, err)
		log.Debug(msg)
		return nil, cop.NewError(cop.CFSSL, msg)
	}
	req.Header.Set("content-type", "application/json")
	c.addTokenAuthHdr(req, reqBodyBytes)
	httpClient := &http.Client{}
	// TODO: Add TLS
	resp, err := httpClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("failed POST to %s: %v", curl, err)
		log.Debug(msg)
		return nil, cop.NewError(cop.CFSSL, msg)
	}
	defer resp.Body.Close()
	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("failed to read response of %s: %v", curl, err)
		log.Debug(msg)
		return respBody, cop.NewError(cop.CFSSL, msg)
	}
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("http error code %d for %s", resp.StatusCode, curl)
		log.Debug(msg)
		return respBody, cop.NewError(cop.CFSSL, msg)
	}
	return respBody, nil
}

func (c *Client) getURL(endpoint string) (string, cop.Error) {
	if c.serverAddr == "" {
		log.Debugf("serverAddr is not set when calling %s", endpoint)
		return "", cop.NewError(cop.ServerAddrNotSet, "server address was not set")
	}
	nurl, err := normalizeURL(c.serverAddr)
	if err != nil {
		log.Debugf("error getting server URL: %s", err)
		return "", cop.WrapError(err, cop.CFSSL, "error getting URL for %s", endpoint)
	}
	rtn := fmt.Sprintf("%s/api/v1/cfssl/%s", nurl, endpoint)
	return rtn, nil
}

func normalizeURL(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if u.Opaque != "" {
		u.Host = net.JoinHostPort(u.Scheme, u.Opaque)
		u.Opaque = ""
	} else if u.Path != "" && !strings.Contains(u.Path, ":") {
		u.Host = net.JoinHostPort(u.Path, "8888")
		u.Path = ""
	} else if u.Scheme == "" {
		u.Host = u.Path
		u.Path = ""
	}
	if u.Scheme != "https" {
		u.Scheme = "http"
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		_, port, err = net.SplitHostPort(u.Host + ":8888")
		if err != nil {
			return nil, err
		}
	}
	if port != "" {
		_, err = strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
	}
	return u, nil
}

func getDefaultHomeDir() string {
	home := os.Getenv("COP_HOME")
	if home == "" {
		home = os.Getenv("HOME")
		if home != "" {
			home = home + "/.cop"
		}
	}
	if home == "" {
		home = "/var/hyperledger/production/.cop"
	}
	return home
}
