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

package lib

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/attrmgr"
	"github.com/hyperledger/fabric-ca/lib/tcert"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// serverRequestContext represents an HTTP request/response context in the server
type serverRequestContext struct {
	req            *http.Request
	resp           http.ResponseWriter
	endpoint       *serverEndpoint
	ca             *CA
	enrollmentID   string
	enrollmentCert *x509.Certificate
	body           struct {
		read bool   // true after body is read
		buf  []byte // the body itself
		err  error  // any error from reading the body
	}
}

// newServerRequestContext is the constructor for a serverRequestContext
func newServerRequestContext(r *http.Request, w http.ResponseWriter, se *serverEndpoint) *serverRequestContext {
	return &serverRequestContext{
		req:      r,
		resp:     w,
		endpoint: se,
	}
}

// BasicAuthentication authenticates the caller's username and password
// found in the authorization header and returns the username
func (ctx *serverRequestContext) BasicAuthentication() (string, error) {
	r := ctx.req
	// Get the authorization header
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		return "", newHTTPErr(401, ErrNoAuthHdr, "No authorization header")
	}
	// Extract the username and password from the header
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", newAuthErr(ErrNoUserPass, "No user/pass in authorization header")
	}
	// Get the CA that is targeted by this request
	ca, err := ctx.GetCA()
	if err != nil {
		return "", err
	}
	// Error if max enrollments is disabled for this CA
	log.Debugf("ca.Config: %+v", ca.Config)
	caMaxEnrollments := ca.Config.Registry.MaxEnrollments
	if caMaxEnrollments == 0 {
		return "", newAuthErr(ErrEnrollDisabled, "Enroll is disabled")
	}
	// Get the user info object for this user
	ui, err := ca.registry.GetUser(username, nil)
	if err != nil {
		return "", newAuthErr(ErrInvalidUser, "Failed to get user: %s", err)
	}
	// Check the user's password and max enrollments if supported by registry
	err = ui.Login(password, caMaxEnrollments)
	if err != nil {
		return "", newAuthErr(ErrInvalidPass, "Login failure: %s", err)
	}
	// Store the enrollment ID associated with this server request context
	ctx.enrollmentID = username
	// Return the username
	return username, nil
}

// TokenAuthentication authenticates the caller by token
// in the authorization header.
// Returns the enrollment ID or error.
func (ctx *serverRequestContext) TokenAuthentication() (string, error) {
	r := ctx.req
	// Get the authorization header
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		return "", newHTTPErr(401, ErrNoAuthHdr, "No authorization header")
	}
	// Get the CA
	ca, err := ctx.GetCA()
	if err != nil {
		return "", err
	}
	// Get the request body
	body, err := ctx.ReadBodyBytes()
	if err != nil {
		return "", err
	}
	// Verify the token; the signature is over the header and body
	cert, err2 := util.VerifyToken(ca.csp, authHdr, body)
	if err2 != nil {
		return "", newAuthErr(ErrInvalidToken, "Invalid token in authorization header: %s", err2)
	}
	// Make sure the caller's cert was issued by this CA
	err2 = ca.VerifyCertificate(cert)
	if err2 != nil {
		return "", newAuthErr(ErrUntrustedCertificate, "Untrusted certificate: %s", err2)
	}
	id := util.GetEnrollmentIDFromX509Certificate(cert)
	log.Debugf("Checking for revocation/expiration of certificate owned by '%s'", id)
	// VerifyCertificate ensures that the certificate passed in hasn't
	// expired and checks the CRL for the server.
	expired, checked := revoke.VerifyCertificate(cert)
	if !checked {
		return "", newHTTPErr(401, ErrCertRevokeCheckFailure, "Failed while checking for revocation")
	}
	if expired {
		return "", newAuthErr(ErrCertExpired,
			"The certificate in the authorization header is a revoked or expired certificate")
	}
	aki := hex.EncodeToString(cert.AuthorityKeyId)
	serial := util.GetSerialAsHex(cert.SerialNumber)
	aki = strings.ToLower(strings.TrimLeft(aki, "0"))
	serial = strings.ToLower(strings.TrimLeft(serial, "0"))
	certs, err := ca.CertDBAccessor().GetCertificate(serial, aki)
	if err != nil {
		return "", newHTTPErr(500, ErrCertNotFound, "Failed searching certificates: %s", err)
	}
	if len(certs) == 0 {
		return "", newAuthErr(ErrCertNotFound, "Certificate not found with AKI '%s' and serial '%s'", aki, serial)
	}
	for _, certificate := range certs {
		if certificate.Status == "revoked" {
			return "", newAuthErr(ErrCertRevoked, "The certificate in the authorization header is a revoked certificate")
		}
	}
	ctx.enrollmentID = id
	ctx.enrollmentCert = cert
	log.Debugf("Successful token authentication of '%s'", id)
	return id, nil
}

// GetECert returns the enrollment certificate of the caller, assuming
// token authentication was successful.
func (ctx *serverRequestContext) GetECert() *x509.Certificate {
	return ctx.enrollmentCert
}

// GetCA returns the CA to which this request is targeted
func (ctx *serverRequestContext) GetCA() (*CA, error) {
	if ctx.ca == nil {
		// Get the CA name
		name, err := ctx.getCAName()
		if err != nil {
			return nil, err
		}
		// Get the CA by its name
		ctx.ca, err = ctx.endpoint.Server.GetCA(name)
		if err != nil {
			return nil, err
		}
	}
	return ctx.ca, nil
}

// GetUserinfo returns the caller's requested attribute values and affiliation path
func (ctx *serverRequestContext) GetUserInfo(attrNames []string) ([]tcert.Attribute, []string, error) {
	id := ctx.enrollmentID
	if id == "" {
		return nil, nil, newHTTPErr(500, ErrCallerIsNotAuthenticated, "Caller is not authenticated")
	}
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, nil, err
	}
	user, err := ca.registry.GetUser(id, attrNames)
	if err != nil {
		return nil, nil, err
	}
	var attrs []tcert.Attribute
	for _, name := range attrNames {
		value := user.GetAttribute(name)
		if value != "" {
			attrs = append(attrs, tcert.Attribute{Name: name, Value: value})
		}
	}
	return attrs, user.GetAffiliationPath(), nil
}

// GetAttrExtension returns an attribute extension to place into a signing request
func (ctx *serverRequestContext) GetAttrExtension(attrReqs []*api.AttributeRequest, profile string) (*signer.Extension, error) {
	if attrReqs == nil {
		return nil, nil
	}
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	ui, err := ca.registry.GetUserInfo(ctx.enrollmentID)
	if err != nil {
		return nil, err
	}
	attrs, err := ca.attrMgr.ProcessAttributeRequests(
		convertAttrReqs(attrReqs),
		convertAttrs(ui.Attributes),
	)
	if err != nil {
		return nil, err
	}
	if attrs != nil {
		buf, err := json.Marshal(attrs)
		if err != nil {
			errors.Wrap(err, "Failed to marshal attributes")
		}
		ext := &signer.Extension{
			ID:       config.OID(attrmgr.AttrOID),
			Critical: false,
			Value:    hex.EncodeToString(buf),
		}
		log.Debugf("GetAttrExtension: extension=%+v", ext)
		return ext, nil
	}
	return nil, nil
}

// caNameReqBody is a sparse request body to unmarshal only the CA name
type caNameReqBody struct {
	CAName string `json:"caname,omitempty"`
}

// getCAName returns the targeted CA name for this request
func (ctx *serverRequestContext) getCAName() (string, error) {
	// Check the query parameters first
	ca := ctx.req.URL.Query().Get("ca")
	if ca != "" {
		return ca, nil
	}
	// Next, check the request body, if there is one
	var body caNameReqBody
	_, err := ctx.TryReadBody(&body)
	if err != nil {
		return "", err
	}
	if body.CAName != "" {
		return body.CAName, nil
	}
	// No CA name in the request body either, so use the default CA name
	return ctx.endpoint.Server.CA.Config.CA.Name, nil
}

// ReadBody reads the request body and JSON unmarshals into 'body'
func (ctx *serverRequestContext) ReadBody(body interface{}) error {
	empty, err := ctx.TryReadBody(body)
	if err != nil {
		return err
	}
	if empty {
		return newHTTPErr(400, ErrEmptyReqBody, "Empty request body")
	}
	return nil
}

// TryReadBody reads the request body into 'body' if not empty
func (ctx *serverRequestContext) TryReadBody(body interface{}) (bool, error) {
	buf, err := ctx.ReadBodyBytes()
	if err != nil {
		return false, err
	}
	empty := len(buf) == 0
	if !empty {
		err = json.Unmarshal(buf, body)
		if err != nil {
			return true, newHTTPErr(400, ErrBadReqBody, "Invalid request body: %s; body=%s",
				err, string(buf))
		}
	}
	return empty, nil
}

// ReadBodyBytes reads the request body and returns bytes
func (ctx *serverRequestContext) ReadBodyBytes() ([]byte, error) {
	if !ctx.body.read {
		r := ctx.req
		buf, err := ioutil.ReadAll(r.Body)
		ctx.body.buf = buf
		ctx.body.err = err
		ctx.body.read = true
	}
	err := ctx.body.err
	if err != nil {
		return nil, newHTTPErr(400, ErrReadingReqBody, "Failed reading request body: %s", err)
	}
	return ctx.body.buf, nil
}

func convertAttrReqs(attrReqs []*api.AttributeRequest) []attrmgr.AttributeRequest {
	rtn := make([]attrmgr.AttributeRequest, len(attrReqs))
	for i := range attrReqs {
		rtn[i] = attrmgr.AttributeRequest(attrReqs[i])
	}
	return rtn
}

func convertAttrs(attrs []api.Attribute) []attrmgr.Attribute {
	rtn := make([]attrmgr.Attribute, len(attrs))
	for i := range attrs {
		rtn[i] = attrmgr.Attribute(&attrs[i])
	}
	return rtn
}
