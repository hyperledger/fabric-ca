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
	secret, err := registerUser(&req, callerID, ca, ctx)
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
func registerUser(req *api.RegistrationRequestNet, registrar string, ca *CA, ctx *serverRequestContext) (string, error) {
	var err error
	var registrarUser spi.User

	registrarUser, err = ctx.GetCaller()
	if err != nil {
		return "", err
	}
	// Check the permissions of member named 'registrar' to perform this registration
	err = canRegister(registrar, req, registrarUser)
	if err != nil {
		log.Debugf("Registration of '%s' failed: %s", req.Name, err)
		return "", err
	}

	// Check that the affiliation requested is of the appropriate level
	registrarAff := GetUserAffiliation(registrarUser)
	err = validateAffiliation(registrarAff, req)
	if err != nil {
		return "", fmt.Errorf("Registration of '%s' failed in affiliation validation: %s", req.Name, err)
	}

	err = validateID(req, ca)
	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Registration of '%s' to validate", req.Name))
	}

	err = validateRequestedAttributes(req.Attributes, registrarUser)
	if err != nil {
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

func validateAffiliation(registrarAff string, req *api.RegistrationRequestNet) error {
	log.Debug("Validate Affiliation")
	if req.Affiliation == "" {
		log.Debugf("No affiliation provided in registeration request, will default to using registrar's affiliation of '%s'", registrarAff)
		req.Affiliation = registrarAff
	} else {
		log.Debugf("Affiliation of '%s' specified in registration request", req.Affiliation)
		if registrarAff != "" {
			log.Debug("Registrar does not have absolute root affiliation path, checking to see if registrar has proper authority to register requested affiliation")
			if !strings.Contains(req.Affiliation, registrarAff) {
				return fmt.Errorf("Registrar does not have authority to request '%s' affiliation", req.Affiliation)
			}
		} else if req.Affiliation == "." {
			// Affiliation request of '.' signifies request for root affiliation
			req.Affiliation = ""
		}
	}

	return nil
}

func validateID(req *api.RegistrationRequestNet, ca *CA) error {
	log.Debug("Validate ID")
	// Check whether the affiliation is required for the current user.
	if requireAffiliation(req.Type) {
		// If yes, is the affiliation valid
		err := isValidAffiliation(req.Affiliation, ca)
		if err != nil {
			return err
		}
	}
	return nil
}

// registerUserID registers a new user and its enrollmentID, role and state
func registerUserID(req *api.RegistrationRequestNet, ca *CA) (string, error) {
	log.Debugf("Registering user id: %s\n", req.Name)
	var err error

	if req.Secret == "" {
		req.Secret = util.RandomString(12)
	}

	req.MaxEnrollments, err = getMaxEnrollments(req.MaxEnrollments, ca.Config.Registry.MaxEnrollments)
	if err != nil {
		return "", err
	}

	// Make sure delegateRoles is not larger than roles
	roles := GetAttrValue(req.Attributes, attrRoles)
	delegateRoles := GetAttrValue(req.Attributes, attrDelegateRoles)
	err = util.IsSubsetOf(delegateRoles, roles)
	if err != nil {
		return "", errors.WithMessage(err, "The delegateRoles field is a superset of roles")
	}

	// Add attributes containing the enrollment ID, type, and affiliation if not
	// already defined
	addAttributeToRequest("hf.EnrollmentID", req.Name, req)
	addAttributeToRequest("hf.Type", req.Type, req)
	addAttributeToRequest("hf.Affiliation", req.Affiliation, req)

	insert := spi.UserInfo{
		Name:           req.Name,
		Pass:           req.Secret,
		Type:           req.Type,
		Affiliation:    req.Affiliation,
		Attributes:     req.Attributes,
		MaxEnrollments: req.MaxEnrollments,
	}

	registry := ca.registry

	_, err = registry.GetUser(req.Name, nil)
	if err == nil {
		return "", errors.Errorf("Identity '%s' is already registered", req.Name)
	}

	err = registry.InsertUser(insert)
	if err != nil {
		return "", err
	}

	return req.Secret, nil
}

func isValidAffiliation(affiliation string, ca *CA) error {
	log.Debug("Validating affiliation: " + affiliation)

	// If requested affiliation is for root then don't need to do lookup in affiliaton's table
	if affiliation == "" {
		return nil
	}

	_, err := ca.registry.GetAffiliation(affiliation)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed getting affiliation '%s'", affiliation))
	}

	return nil
}

func requireAffiliation(idType string) bool {
	log.Debugf("An affiliation is required for identity type %s", idType)
	// Require an affiliation for all identity types
	return true
}

func canRegister(registrar string, req *api.RegistrationRequestNet, user spi.User) error {
	log.Debugf("canRegister - Check to see if user %s can register", registrar)

	var roles []string
	rolesStr, err := user.GetAttribute("hf.Registrar.Roles")
	if err != nil {
		return errors.Errorf("Failed to get attribute 'hf.Registrar.Roles': %s", err)
	}
	if rolesStr.Value != "" {
		roles = strings.Split(rolesStr.Value, ",")
	} else {
		roles = make([]string, 0)
	}
	if req.Type == "" {
		req.Type = "client"
	}
	if !util.StrContained(req.Type, roles) {
		return fmt.Errorf("Identity '%s' may not register type '%s'", registrar, req.Type)
	}
	return nil
}

// Validate that the registrar can register the requested attributes
func validateRequestedAttributes(reqAttrs []api.Attribute, registrar spi.User) error {
	registrarCanRegisterAttrs, err := registrar.GetAttribute(attrRegistrarAttr)
	if err != nil {
		return newHTTPErr(401, ErrMissingRegAttr, "Registrar does not have attribute '%s' thus can't register any attributes", attrRegistrarAttr)
	}
	registrarAttrs := registrarCanRegisterAttrs.Value
	log.Debugf("Validating that registrar '%s' with the following value for hf.Registrar.Attributes '%s' is authorized to register the requested attributes '%+v'", registrar.GetName(), registrarAttrs, reqAttrs)
	if len(reqAttrs) == 0 {
		return nil
	}

	if registrarAttrs == "" {
		return newHTTPErr(401, ErrMissingRegAttr, "Registrar does not have any values for '%s' thus can't register any attributes", attrRegistrarAttr)
	}

	hfRegistrarAttrsSlice := strings.Split(strings.Replace(registrarAttrs, " ", "", -1), ",") // Remove any whitespace between the values and split on comma

	// Function will iterate through the values of registrar's 'hf.Registrar.Attributes' attribute to check if registrar can register the requested attributes
	registrarCanRegisterAttr := func(requestedAttr string) error {
		for _, regAttr := range hfRegistrarAttrsSlice {
			if strings.HasSuffix(regAttr, "*") { // Wildcard matching
				if strings.HasPrefix(requestedAttr, strings.TrimRight(regAttr, "*")) {
					return nil // Requested attribute found, break out of loop
				}
			} else {
				if requestedAttr == regAttr { // Exact name matching
					return nil // Requested attribute found, break out of loop
				}
			}
		}
		return errors.Errorf("Attribute is not part of '%s' attribute", attrRegistrarAttr)
	}

	for _, reqAttr := range reqAttrs {
		reqAttrName := reqAttr.Name // Name of the requested attribute

		// Requesting 'hf.Registrar.Attributes' attribute
		if reqAttrName == attrRegistrarAttr {
			// Check if registrar is allowed to register 'hf.Registrar.Attribute' by examining it's value for 'hf.Registrar.Attribute'
			err := registrarCanRegisterAttr(attrRegistrarAttr)
			if err != nil {
				return newHTTPErr(401, ErrRegAttrAuth, "Registrar is not allowed to register attribute '%s': %s", reqAttrName, err)
			}

			reqRegistrarAttrsSlice := strings.Split(strings.Replace(reqAttr.Value, " ", "", -1), ",") // Remove any whitespace between the values and split on comma
			// Loop through the requested values for 'hf.Registrar.Attributes' to see if they can be registered
			for _, reqRegistrarAttr := range reqRegistrarAttrsSlice {
				err := registrarCanRegisterAttr(reqRegistrarAttr)
				if err != nil {
					return newHTTPErr(401, ErrRegAttrAuth, "Registrar is not allowed to register attribute '%s': %s", reqAttrName, err)
				}
			}
			continue // Continue to next requested attribute
		}

		// Iterate through the registrar's value for 'hf.Registrar.Attributes' to check if it can register the requested attribute
		err := registrarCanRegisterAttr(reqAttrName)
		if err != nil {
			return newHTTPErr(401, ErrRegAttrAuth, "Registrar is not allowed to register attribute '%s': %s", reqAttrName, err)
		}
	}

	return nil
}

// Add an attribute to the registration request if not already found.
func addAttributeToRequest(name, value string, req *api.RegistrationRequestNet) {
	for _, attr := range req.Attributes {
		if attr.Name == name {
			return
		}
	}
	req.Attributes = append(req.Attributes, api.Attribute{Name: name, Value: value})
}
