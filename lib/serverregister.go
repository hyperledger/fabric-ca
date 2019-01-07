/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"fmt"
	"net/url"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

func newRegisterEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:      "register",
		Methods:   []string{"POST"},
		Handler:   registerHandler,
		Server:    s,
		successRC: 201,
	}
}

// Handle a register request
func registerHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	return register(ctx, ca)
}

func register(ctx ServerRequestContext, ca *CA) (interface{}, error) {
	// Read request body
	var req api.RegistrationRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	log.Debugf("Received registration request from %s: %v", callerID, &req)
	if ctx.IsLDAPEnabled() {
		return nil, caerrors.NewHTTPErr(403, caerrors.ErrInvalidLDAPAction, "Registration is not supported when using LDAP")
	}
	// Register User
	secret, err := registerUser(&req.RegistrationRequest, callerID, ca, ctx)
	if err != nil {
		return nil, err
	}
	// Return response
	resp := &api.RegistrationResponseNet{
		RegistrationResponse: api.RegistrationResponse{Secret: secret},
	}
	return resp, nil
}

// RegisterUser will register a user and return the secret
func registerUser(req *api.RegistrationRequest, registrar string, ca *CA, ctx ServerRequestContext) (string, error) {
	var err error
	var registrarUser user.User

	registrarUser, err = ctx.GetCaller()
	if err != nil {
		return "", err
	}

	normalizeRegistrationRequest(req, registrarUser)

	// Check the permissions of member named 'registrar' to perform this registration
	err = canRegister(registrarUser, req, ca, ctx)
	if err != nil {
		log.Debugf("Registration of '%s' failed: %s", req.Name, err)
		return "", err
	}

	secret, err := registerUserID(req, ca)

	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Registration of '%s' failed", req.Name))
	}
	// Set the location header to the URI of the identity that was created by the registration request
	ctx.GetResp().Header().Set("Location", fmt.Sprintf("%sidentities/%s", apiPathPrefix, url.PathEscape(req.Name)))
	return secret, nil
}

func normalizeRegistrationRequest(req *api.RegistrationRequest, registrar user.User) {
	if req.Affiliation == "" {
		registrarAff := user.GetAffiliation(registrar)
		log.Debugf("No affiliation provided in registration request, will default to using registrar's affiliation of '%s'", registrarAff)
		req.Affiliation = registrarAff
	} else if req.Affiliation == "." {
		// Affiliation request of '.' signifies request for root affiliation
		req.Affiliation = ""
	}

	if req.Type == "" {
		req.Type = registrar.GetType()
	}
}

func validateAffiliation(req *api.RegistrationRequest, ca *CA, ctx ServerRequestContext) error {
	affiliation := req.Affiliation
	log.Debugf("Validating affiliation: %s", affiliation)
	err := ctx.ContainsAffiliation(affiliation)
	if err != nil {
		return err
	}

	// If requested affiliation is for root then don't need to do lookup in affiliation's table
	if affiliation == "" {
		return nil
	}

	_, err = ca.registry.GetAffiliation(affiliation)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed getting affiliation '%s'", affiliation))
	}

	return nil
}

// registerUserID registers a new user and its enrollmentID, role and state
func registerUserID(req *api.RegistrationRequest, ca *CA) (string, error) {
	log.Debugf("Registering user id: %s\n", req.Name)
	var err error

	if req.Secret == "" {
		req.Secret = util.RandomString(12)
	}

	req.MaxEnrollments, err = getMaxEnrollments(req.MaxEnrollments, ca.Config.Registry.MaxEnrollments)
	if err != nil {
		return "", err
	}

	// Add attributes containing the enrollment ID, type, and affiliation if not
	// already defined
	addAttributeToRequest(attr.EnrollmentID, req.Name, &req.Attributes)
	addAttributeToRequest(attr.Type, req.Type, &req.Attributes)
	addAttributeToRequest(attr.Affiliation, req.Affiliation, &req.Attributes)

	insert := user.Info{
		Name:           req.Name,
		Pass:           req.Secret,
		Type:           req.Type,
		Affiliation:    req.Affiliation,
		Attributes:     req.Attributes,
		MaxEnrollments: req.MaxEnrollments,
		Level:          ca.server.levels.Identity,
	}

	registry := ca.registry

	_, err = registry.GetUser(req.Name, nil)
	if err == nil {
		return "", errors.Errorf("Identity '%s' is already registered", req.Name)
	}

	err = registry.InsertUser(&insert)
	if err != nil {
		return "", err
	}

	return req.Secret, nil
}

func canRegister(registrar user.User, req *api.RegistrationRequest, ca *CA, ctx ServerRequestContext) error {
	log.Debugf("canRegister - Check to see if user '%s' can register", registrar.GetName())

	err := ctx.CanActOnType(req.Type)
	if err != nil {
		return err
	}
	// Check that the affiliation requested is of the appropriate level
	err = validateAffiliation(req, ca, ctx)
	if err != nil {
		return fmt.Errorf("Registration of '%s' failed in affiliation validation: %s", req.Name, err)
	}

	err = attr.CanRegisterRequestedAttributes(req.Attributes, nil, registrar)
	if err != nil {
		return caerrors.NewAuthorizationErr(caerrors.ErrRegAttrAuth, "Failed to register attribute: %s", err)
	}

	return nil
}

// Add an attribute to the registration request if not already found.
func addAttributeToRequest(name, value string, attributes *[]api.Attribute) {
	*attributes = append(*attributes, api.Attribute{Name: name, Value: value, ECert: true})
}
