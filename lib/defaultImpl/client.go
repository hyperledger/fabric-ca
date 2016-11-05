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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

// NewClient is the constructor for the COP client API
func NewClient(config string) (idp.ClientAPI, error) {
	c := new(Client)
	err := util.Unmarshal([]byte(config), c, "NewClient")
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Client is COP's implementation of the idp.ClientAPI interface which is the
// client-side of an identity provider (IDP)
type Client struct {
	ServerAddr string `json:"serverAddr"`
}

// Capabilities returns the capabilities COP
func (c *Client) Capabilities() []idp.Capability {
	return []idp.Capability{
		idp.REGISTRATION,
		idp.ENROLLMENT,
		idp.ATTRIBUTES,
		idp.ANONYMITY,
		idp.UNLINKABILITY,
	}
}

// Register registers a new identity
// @param req The registration request
func (c *Client) Register(req *idp.RegistrationRequest) (*idp.RegistrationResponse, error) {
	log.Debugf("Register %+v", req)
	// Send a post to the "register" endpoint with req as body
	buf, err := req.Registrar.(*Identity).post("register", req)
	if err != nil {
		return nil, err
	}
	resp := new(idp.RegistrationResponse)
	err = util.Unmarshal(buf, resp, "idp.RegistrationResponse")
	if err != nil {
		return nil, err
	}
	log.Debug("Register success")
	return resp, nil
}

// Enroll enrolls a new identity
// @param req The enrollment request
func (c *Client) Enroll(req *idp.EnrollmentRequest) (idp.Identity, error) {
	log.Debugf("Enrolling %+v", req)

	cr := req.CR
	if cr == nil {
		cr = csr.New()
		cr.CN = req.Name
		cr.Hosts = req.Hosts
	}

	csrPEM, key, err := csr.ParseRequest(cr)
	if err != nil {
		log.Debugf("enroll failure parsing request: %s", err)
		return nil, err
	}

	post, err := c.newPost("enroll", csrPEM)
	if err != nil {
		return nil, err
	}
	post.SetBasicAuth(req.Name, req.Secret)
	cert, err := c.sendPost(post)
	if err != nil {
		return nil, err
	}

	log.Debug("enroll success")

	return newIdentity(c, req.Name, key, cert), nil
}

// RegisterAndEnroll registers and enrolls a new identity
// @param req The registration request
func (c *Client) RegisterAndEnroll(req *idp.RegistrationRequest) (idp.Identity, error) {
	return nil, errors.New("NotImplemented")
}

// ImportSigner imports a signer from an external CA
// @param req The import request
func (c *Client) ImportSigner(req *idp.ImportSignerRequest) (idp.Signer, error) {
	return nil, errors.New("NotImplemented")
}

// DeserializeIdentity deserializes an identity
func (c *Client) DeserializeIdentity([]byte) (idp.Identity, error) {
	return nil, errors.New("NotImplemented")
}

// Create a new request
func (c *Client) newPost(endpoint string, reqBody []byte) (*http.Request, error) {
	curl, cerr := c.getURL(endpoint)
	if cerr != nil {
		return nil, cerr
	}
	req, err := http.NewRequest("POST", curl, bytes.NewReader(reqBody))
	if err != nil {
		msg := fmt.Sprintf("failed to create new request to %s: %v", curl, err)
		log.Debug(msg)
		return nil, cop.NewError(cop.CFSSL, msg)
	}
	return req, nil
}

func (c *Client) sendPost(req *http.Request) (respBody []byte, err error) {
	log.Debugf("Sending request\n%s", util.HTTPRequestToString(req))
	req.Header.Set("content-type", "application/json")
	httpClient := &http.Client{}
	// TODO: Add TLS
	resp, err := httpClient.Do(req)
	if err != nil {
		msg := fmt.Sprintf("failed POST: %v", err)
		log.Debug(msg)
		return nil, cop.NewError(cop.CFSSL, msg)
	}
	defer resp.Body.Close()
	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("failed to read response: %v", err)
		log.Debug(msg)
		return respBody, cop.NewError(cop.CFSSL, msg)
	}
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("http error code %d", resp.StatusCode)
		log.Debug(msg)
		return respBody, cop.NewError(cop.CFSSL, msg)
	}
	return respBody, nil
}

func (c *Client) getURL(endpoint string) (string, cop.Error) {
	nurl, err := normalizeURL(c.ServerAddr)
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
