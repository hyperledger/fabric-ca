/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/common"
	"github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/user"
)

func newIdemixEnrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:      "idemix/credential",
		Methods:   []string{"POST"},
		Handler:   handleIdemixEnrollReq,
		Server:    s,
		successRC: 201,
	}
}

// handleIdemixEnrollReq handles an Idemix enroll request
func handleIdemixEnrollReq(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}

	idemixEnrollResp, err := ca.issuer.IssueCredential(&idemixServerCtx{ctx})
	if err != nil {
		log.Errorf("Error processing the /idemix/credential request: %s", err.Error())
		return nil, err
	}
	resp := newIdemixEnrollmentResponseNet(idemixEnrollResp)
	err = ctx.ca.fillCAInfo(&resp.CAInfo)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// newIdemixEnrollmentResponseNet returns an instance of IdemixEnrollmentResponseNet that is
// constructed using the specified idemix.EnrollmentResponse object
func newIdemixEnrollmentResponseNet(resp *idemix.EnrollmentResponse) common.IdemixEnrollmentResponseNet {
	return common.IdemixEnrollmentResponseNet{
		Nonce:      resp.Nonce,
		Attrs:      resp.Attrs,
		Credential: resp.Credential,
		CRI:        resp.CRI,
		CAInfo:     common.CAInfoResponseNet{}}
}

// idemixServerCtx implements idemix.ServerRequestContext
type idemixServerCtx struct {
	srvCtx *serverRequestContextImpl
}

func (c *idemixServerCtx) IsBasicAuth() bool {
	_, _, isBasicAuth := c.srvCtx.req.BasicAuth()
	return isBasicAuth
}
func (c *idemixServerCtx) BasicAuthentication() (string, error) {
	return c.srvCtx.BasicAuthentication()
}
func (c *idemixServerCtx) TokenAuthentication() (string, error) {
	return c.srvCtx.TokenAuthentication()
}
func (c *idemixServerCtx) GetCaller() (user.User, error) {
	return c.srvCtx.GetCaller()
}
func (c *idemixServerCtx) ReadBody(body interface{}) error {
	return c.srvCtx.ReadBody(body)
}
