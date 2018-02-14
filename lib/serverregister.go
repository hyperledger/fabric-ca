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
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
)

func newRegisterEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"POST"},
		Handler:   registerHandler,
		Server:    s,
		successRC: 201,
	}
}

// Handle a register request
func registerHandler(ctx *serverRequestContext) (interface{}, error) {
	// Read request body
	var req api.RegistrationRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	log.Debugf("Received registration request from %s: %v", callerID, &req)
	if err != nil {
		return nil, err
	}
	// Get the target CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
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
func registerUser(req *api.RegistrationRequest, registrar string, ca *CA, ctx *serverRequestContext) (string, error) {
	var err error
	var registrarUser spi.User

	registrarUser, err = ctx.GetCaller()
	if err != nil {
		return "", err
	}

	normalizeRegistrationRequest(req, registrarUser)

	// Check the permissions of member named 'registrar' to perform this registration
	err = canRegister(registrarUser, req, ctx)
	if err != nil {
		log.Debugf("Registration of '%s' failed: %s", req.Name, err)
		return "", err
	}

	secret, err := registerUserID(req, ca)

	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Registration of '%s' failed", req.Name))
	}
	// Set the location header to the URI of the identity that was created by the registration request
	ctx.resp.Header().Set("Location", fmt.Sprintf("%sidentities/%s", apiPathPrefix, url.PathEscape(req.Name)))
	return secret, nil
}

func normalizeRegistrationRequest(req *api.RegistrationRequest, registrar spi.User) {
	if req.Affiliation == "" {
		registrarAff := GetUserAffiliation(registrar)
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

func validateAffiliation(req *api.RegistrationRequest, ctx *serverRequestContext) error {
	log.Debug("Validate Affiliation")
	err := ctx.ContainsAffiliation(req.Affiliation)
	if err != nil {
		return err
	}
	return nil
}

func validateID(req *api.RegistrationRequest, ca *CA) error {
	log.Debug("Validate ID")
	err := isValidAffiliation(req.Affiliation, ca)
	if err != nil {
		return err
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

	insert := spi.UserInfo{
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

func isValidAffiliation(affiliation string, ca *CA) error {
	log.Debugf("Validating affiliation: %s", affiliation)

	// If requested affiliation is for root then don't need to do lookup in affiliation's table
	if affiliation == "" {
		return nil
	}

	_, err := ca.registry.GetAffiliation(affiliation)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed getting affiliation '%s'", affiliation))
	}

	return nil
}

func canRegister(registrar spi.User, req *api.RegistrationRequest, ctx *serverRequestContext) error {
	log.Debugf("canRegister - Check to see if user '%s' can register", registrar.GetName())

	var roles []string
	rolesStr, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		return err
	}
	if !isRegistrar {
		return errors.Errorf("'%s' does not have authority to register identities", registrar)
	}
	if rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	} else {
		roles = make([]string, 0)
	}
	if req.Type == "" {
		req.Type = "client"
	}
	if !util.StrContained(req.Type, roles) {
		return fmt.Errorf("Identity '%s' may not register type '%s'", registrar, req.Type)
	}

	// Check that the affiliation requested is of the appropriate level
	err = validateAffiliation(req, ctx)
	if err != nil {
		return fmt.Errorf("Registration of '%s' failed in affiliation validation: %s", req.Name, err)
	}

	err = validateID(req, ctx.ca)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Registration of '%s' to validate", req.Name))
	}

	err = attr.CanRegisterRequestedAttributes(req.Attributes, nil, registrar)
	if err != nil {
		return newAuthErr(ErrRegAttrAuth, "Failed to register attribute: %s", err)
	}

	return nil
}

// Add an attribute to the registration request if not already found.
func addAttributeToRequest(name, value string, attributes *[]api.Attribute) {
	*attributes = append(*attributes, api.Attribute{Name: name, Value: value, ECert: true})
}
