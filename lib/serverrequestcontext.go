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
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/cloudflare/cfssl/signer"
	gmux "github.com/gorilla/mux"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/common/attrmgr"
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
	ui             spi.User
	caller         spi.User
	body           struct {
		read bool   // true after body is read
		buf  []byte // the body itself
		err  error  // any error from reading the body
	}
	callerRoles map[string]bool
}

const (
	registrarRole = "hf.Registrar.Roles"
)

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
	ctx.ui, err = ca.registry.GetUser(username, nil)
	if err != nil {
		return "", newAuthErr(ErrInvalidUser, "Failed to get user: %s", err)
	}
	// Check the user's password and max enrollments if supported by registry
	err = ctx.ui.Login(password, caMaxEnrollments)
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

// GetCA returns the CA to which this request is targeted and checks to make sure the database has been initialized
func (ctx *serverRequestContext) GetCA() (*CA, error) {
	_, err := ctx.getCA()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get CA instance")
	}
	if !ctx.ca.dbInitialized {
		err := ctx.ca.initDB()
		if err != nil {
			return nil, errors.WithMessage(err, fmt.Sprintf("%s handler failed to initialize DB", strings.TrimLeft(ctx.req.URL.String(), "/")))
		}
	}
	return ctx.ca, nil
}

// GetCA returns the CA to which this request is targeted
func (ctx *serverRequestContext) getCA() (*CA, error) {
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

// GetAttrExtension returns an attribute extension to place into a signing request
func (ctx *serverRequestContext) GetAttrExtension(attrReqs []*api.AttributeRequest, profile string) (*signer.Extension, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	ui, err := ca.registry.GetUser(ctx.enrollmentID, nil)
	if err != nil {
		return nil, err
	}
	allAttrs, _ := ui.GetAttributes(nil)
	if attrReqs == nil {
		attrReqs = getDefaultAttrReqs(allAttrs)
		if attrReqs == nil {
			// No attributes are being requested, so we are done
			return nil, nil
		}
	}
	attrs, err := ca.attrMgr.ProcessAttributeRequests(
		convertAttrReqs(attrReqs),
		convertAttrs(allAttrs),
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
		log.Debugf("Attribute extension being added to certificate is: %+v", ext)
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

func (ctx *serverRequestContext) GetUser(userName string) (spi.User, error) {
	ca, err := ctx.getCA()
	if err != nil {
		return nil, err
	}
	registry := ca.registry

	user, err := registry.GetUser(userName, nil)
	if err != nil {
		return nil, err
	}

	err = ctx.CanManageUser(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// CanManageUser determines if the caller has the right type and affiliation to act on on a user
func (ctx *serverRequestContext) CanManageUser(user spi.User) error {
	userAff := strings.Join(user.GetAffiliationPath(), ".")
	err := ctx.ContainsAffiliation(userAff)
	if err != nil {
		return err
	}

	userType := user.GetType()
	err = ctx.CanActOnType(userType)
	if err != nil {
		return err
	}

	return nil
}

// CanModifyUser determines if the modifications to the user are allowed
func (ctx *serverRequestContext) CanModifyUser(req *api.ModifyIdentityRequest, checkAff bool, checkType bool, checkAttrs bool, userToModify spi.User) error {
	if checkAff {
		reqAff := req.Affiliation
		log.Debugf("Checking if caller is authorized to change affiliation to '%s'", reqAff)
		err := ctx.ContainsAffiliation(reqAff)
		if err != nil {
			return err
		}
	}

	if checkType {
		reqType := req.Type
		log.Debugf("Checking if caller is authorized to change type to '%s'", reqType)
		err := ctx.CanActOnType(reqType)
		if err != nil {
			return err
		}
	}

	if checkAttrs {
		reqAttrs := req.Attributes
		log.Debugf("Checking if caller is authorized to change attributes to %+v", reqAttrs)
		err := attr.CanRegisterRequestedAttributes(reqAttrs, userToModify, ctx.caller)
		if err != nil {
			return newAuthErr(ErrRegAttrAuth, "Failed to register attributes: %s", err)
		}
	}

	return nil
}

// GetCaller gets the user who is making this server request
func (ctx *serverRequestContext) GetCaller() (spi.User, error) {
	if ctx.caller != nil {
		return ctx.caller, nil
	}

	var err error
	id := ctx.enrollmentID
	if id == "" {
		return nil, newAuthErr(ErrCallerIsNotAuthenticated, "Caller is not authenticated")
	}
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Get the user info object for this user
	ctx.caller, err = ca.registry.GetUser(id, nil)
	if err != nil {
		return nil, newAuthErr(ErrGettingUser, "Failed to get user")
	}
	return ctx.caller, nil
}

// ContainsAffiliation returns an error if the requested affiliation does not contain the caller's affiliation
func (ctx *serverRequestContext) ContainsAffiliation(affiliation string) error {
	validAffiliation, err := ctx.containsAffiliation(affiliation)
	if err != nil {
		return newHTTPErr(500, ErrGettingAffiliation, "Failed to validate if caller has authority to get ID: %s", err)
	}
	if !validAffiliation {
		return newAuthErr(ErrCallerNotAffiliated, "Caller does not have authority to act on affiliation '%s'", affiliation)
	}
	return nil
}

// containsAffiliation returns true if the requested affiliation contains the caller's affiliation
func (ctx *serverRequestContext) containsAffiliation(affiliation string) (bool, error) {
	caller, err := ctx.GetCaller()
	if err != nil {
		return false, err
	}

	callerAffiliationPath := GetUserAffiliation(caller)
	log.Debugf("Checking to see if affiliation '%s' contains caller's affiliation '%s'", affiliation, callerAffiliationPath)

	// If the caller has root affiliation return "true"
	if callerAffiliationPath == "" {
		log.Debug("Caller has root affiliation")
		return true, nil
	}

	if affiliation == callerAffiliationPath {
		return true, nil
	}

	callerAffiliationPath = callerAffiliationPath + "."
	if strings.HasPrefix(affiliation, callerAffiliationPath) {
		return true, nil
	}

	return false, nil
}

// IsRegistrar returns an error if the caller is not a registrar
func (ctx *serverRequestContext) IsRegistrar() error {
	_, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		return err
	}
	if !isRegistrar {
		return newAuthErr(ErrMissingRegAttr, "Caller is not a registrar")
	}

	return nil
}

// isRegistrar returns back true if the caller is a registrar along with the types the registrar is allowed to register
func (ctx *serverRequestContext) isRegistrar() (string, bool, error) {
	caller, err := ctx.GetCaller()
	if err != nil {
		return "", false, err
	}

	log.Debugf("Checking to see if caller '%s' is a registrar", caller.GetName())

	rolesStr, err := caller.GetAttribute("hf.Registrar.Roles")
	if err != nil {
		return "", false, newAuthErr(ErrRegAttrAuth, "'%s' is not a registrar", caller.GetName())
	}

	// Has some value for attribute 'hf.Registrar.Roles' then user is a registrar
	if rolesStr.Value != "" {
		return rolesStr.Value, true, nil
	}

	return "", false, nil
}

// CanActOnType returns true if the caller has the proper authority to take action on specific type
func (ctx *serverRequestContext) CanActOnType(userType string) error {
	canAct, err := ctx.canActOnType(userType)
	if err != nil {
		return newHTTPErr(500, ErrGettingType, "Failed to verify if user can act on type '%s': %s", userType, err)
	}
	if !canAct {
		return newAuthErr(ErrCallerNotAffiliated, "Registrar does not have authority to act on type '%s'", userType)
	}
	return nil
}

func (ctx *serverRequestContext) canActOnType(requestedType string) (bool, error) {
	caller, err := ctx.GetCaller()
	if err != nil {
		return false, err
	}

	log.Debugf("Checking to see if caller '%s' can act on type '%s'", caller.GetName(), requestedType)

	typesStr, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		return false, err
	}
	if !isRegistrar {
		return false, newAuthErr(ErrRegAttrAuth, "'%s' is not allowed to manage users", caller.GetName())
	}

	var types []string
	if typesStr != "" {
		types = strings.Split(typesStr, ",")
	} else {
		types = make([]string, 0)
	}

	if !util.StrContained(requestedType, types) {
		log.Debugf("Caller with types '%s' is not authorized to act on '%s'", types, requestedType)
		return false, nil
	}

	return true, nil
}

// HasRole returns an error if the caller does not have the attribute or the value is false for a boolean attribute
func (ctx *serverRequestContext) HasRole(role string) error {
	hasRole, err := ctx.hasRole(role)
	if err != nil {
		return err
	}
	if !hasRole {
		return newHTTPErr(400, ErrMissingRole, "Caller has a value of 'false' for attribute/role '%s'", role)
	}
	return nil
}

// HasRole returns true if the caller has the attribute and value of the attribute is true
func (ctx *serverRequestContext) hasRole(role string) (bool, error) {
	if ctx.callerRoles == nil {
		ctx.callerRoles = make(map[string]bool)
	}

	roleStatus, hasRole := ctx.callerRoles[role]
	if hasRole {
		return roleStatus, nil
	}

	caller, err := ctx.GetCaller()
	if err != nil {
		return false, err
	}

	roleAttr, err := caller.GetAttribute(role)
	if err != nil {
		return false, err
	}
	roleStatus, err = strconv.ParseBool(roleAttr.Value)
	if err != nil {
		return false, errors.Wrap(err, fmt.Sprintf("Failed to get boolean value of '%s'", role))
	}
	ctx.callerRoles[role] = roleStatus

	return ctx.callerRoles[role], nil
}

// GetVar returns the parameter path variable from the URL
func (ctx *serverRequestContext) GetVar(name string) (string, error) {
	vars := gmux.Vars(ctx.req)
	if vars == nil {
		return "", newHTTPErr(500, ErrHTTPRequest, "Failed to correctly handle HTTP request")
	}
	value := vars[name]
	return value, nil
}

// GetBoolQueryParm returns query parameter from the URL
func (ctx *serverRequestContext) GetBoolQueryParm(name string) (bool, error) {
	var err error

	value := false
	param := ctx.req.URL.Query().Get(name)
	if param != "" {
		value, err = strconv.ParseBool(param)
		if err != nil {
			return false, newHTTPErr(400, ErrUpdateConfigRemoveAff, "Failed to correctly parse value of '%s' query parameter: %s", name, err)
		}
	}

	return value, nil
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

// Return attribute requests for attributes which should by default be added to an ECert
func getDefaultAttrReqs(attrs []api.Attribute) []*api.AttributeRequest {
	count := 0
	for _, attr := range attrs {
		if attr.ECert {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	reqs := make([]*api.AttributeRequest, count)
	count = 0
	for _, attr := range attrs {
		if attr.ECert {
			reqs[count] = &api.AttributeRequest{Name: attr.Name}
			count++
		}
	}
	return reqs
}
