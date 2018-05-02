/*
Copyright IBM Corp. 2018 All Rights Reserved.

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
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/spi"
)

// IdemixEnrollmentResponseNet is the idemix enrollment response from the server
type IdemixEnrollmentResponseNet struct {
	// Base64 encoding of idemix Credential
	Credential string
	// Attribute name-value pairs
	Attrs map[string]string
	// Base64 encoding of Credential Revocation list
	//CRL string
	// Base64 encoding of the issuer nonce
	Nonce string
	// The server information
	ServerInfo ServerInfoResponseNet
}

func newIdemixEnrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"POST"},
		Handler:   handleIdemixEnrollReq,
		Server:    s,
		successRC: 201,
	}
}

// handleIdemixEnrollReq handles an Idemix enroll request
func handleIdemixEnrollReq(ctx *serverRequestContextImpl) (interface{}, error) {
	_, _, isBasicAuth := ctx.req.BasicAuth()
	handler := idemix.EnrollRequestHandler{
		Ctx:         &idemixServerCtx{ctx},
		IsBasicAuth: isBasicAuth,
		IdmxLib:     idemix.NewLib(),
	}

	idemixEnrollResp, err := handler.HandleIdemixEnroll()
	if err != nil {
		log.Errorf("Error processing the /idemix/credential request: %s", err.Error())
		return nil, err
	}
	resp := newIdemixEnrollmentResponseNet(idemixEnrollResp)
	err = ctx.ca.fillCAInfo(&resp.ServerInfo)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// newIdemixEnrollmentResponseNet returns an instance of IdemixEnrollmentResponseNet that is
// constructed using the specified idemix.EnrollmentResponse object
func newIdemixEnrollmentResponseNet(resp *idemix.EnrollmentResponse) IdemixEnrollmentResponseNet {
	return IdemixEnrollmentResponseNet{
		Nonce:      resp.Nonce,
		Attrs:      resp.Attrs,
		Credential: resp.Credential,
		ServerInfo: ServerInfoResponseNet{}}
}

// idemixServerCtx implements idemix.ServerRequestContext
type idemixServerCtx struct {
	srvCtx *serverRequestContextImpl
}

func (c *idemixServerCtx) BasicAuthentication() (string, error) {
	return c.srvCtx.BasicAuthentication()
}
func (c *idemixServerCtx) TokenAuthentication() (string, error) {
	return c.srvCtx.TokenAuthentication()
}
func (c *idemixServerCtx) GetCA() (idemix.CA, error) {
	return c.srvCtx.GetCA()
}
func (c *idemixServerCtx) GetCaller() (spi.User, error) {
	return c.srvCtx.GetCaller()
}
func (c *idemixServerCtx) ReadBody(body interface{}) error {
	return c.srvCtx.ReadBody(body)
}
