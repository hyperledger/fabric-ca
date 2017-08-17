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
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
)

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
	if err != nil {
		return nil, err
	}
	// Get the target CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Register User
	secret, err := registerUser(&req, callerID, ca)
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
func registerUser(req *api.RegistrationRequestNet, registrar string, ca *CA) (string, error) {

	secret := req.Secret
	req.Secret = "<<user-specified>>"
	log.Debugf("Received registration request from %s: %+v", registrar, req)
	req.Secret = secret

	var err error

	if registrar != "" {
		// Check the permissions of member named 'registrar' to perform this registration
		err = canRegister(registrar, req.Type, ca)
		if err != nil {
			log.Debugf("Registration of '%s' failed: %s", req.Name, err)
			return "", err
		}
	}

	err = validateID(req, ca)
	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Registration of '%s' to validate", req.Name))
	}

	secret, err = registerUserID(req, ca)

	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Registration of '%s' failed", req.Name))
	}

	return secret, nil
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

func canRegister(registrar string, userType string, ca *CA) error {
	log.Debugf("canRegister - Check to see if user %s can register", registrar)

	user, err := ca.registry.GetUser(registrar, nil)
	if err != nil {
		return errors.WithMessage(err, "Registrar does not exist")
	}

	var roles []string
	rolesStr := user.GetAttribute("hf.Registrar.Roles")
	if rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	} else {
		roles = make([]string, 0)
	}
	if userType != "" {
		if !util.StrContained(userType, roles) {
			return errors.Errorf("Identity '%s' may not register type '%s'", registrar, userType)
		}
	} else {
		return errors.New("No identity type provided. Please provide identity type")
	}

	return nil
}
