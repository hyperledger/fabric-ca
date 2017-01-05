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

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"

	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/server/spi"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

// registerHandler for register requests
type registerHandler struct {
}

// NewRegisterHandler is constructor for register handler
func NewRegisterHandler() (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &api.HTTPHandler{
		Handler: &registerHandler{},
		Methods: []string{"POST"},
	}, nil
}

// Handle a register request
func (h *registerHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("Register request received")

	reg := NewRegisterUser()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Parse request body
	var req cop.RegisterRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return err
	}

	// Register User
	tok, err := reg.RegisterUser(req.User, req.Type, req.Group, req.Attributes, req.CallerID)
	if err != nil {
		log.Error("Error occured during register of user, error: ", err)
		return err
	}

	log.Debug("Registration completed - Sending response to clients")
	return api.SendResponse(w, []byte(tok))
}

// Register for registering a user
type Register struct {
	cfg *Config
}

const (
	roles          string = "roles"
	peer           string = "peer"
	client         string = "client"
	registrarRoles string = "hf.Registrar.Roles"
)

// NewRegisterUser is a constructor
func NewRegisterUser() *Register {
	r := new(Register)
	r.cfg = CFG
	return r
}

// RegisterUser will register a user
func (r *Register) RegisterUser(id string, userType string, group string, attributes []idp.Attribute, registrar string, opt ...string) (string, error) {
	log.Debugf("Received request to register user with id: %s, group: %s, attributes: %s, registrar: %s\n",
		id, group, attributes, registrar)

	var tok string
	var err error

	if registrar != "" {
		// Check the permissions of member named 'registrar' to perform this registration
		err = r.canRegister(registrar, userType)
		if err != nil {
			return "", err
		}
	}

	err = r.validateID(id, userType, group)
	if err != nil {
		return "", err
	}

	tok, err = r.registerUserID(id, userType, group, attributes, opt...)

	if err != nil {
		return "", err
	}

	return tok, nil
}

// func (r *Register) validateAndGenerateEnrollID(id, group string, attr []idp.Attribute) (string, error) {
func (r *Register) validateID(id string, userType string, group string) error {
	log.Debug("Validate ID")
	// Check whether the group is required for the current user.

	// group is required if the type is client or peer.
	// group is not required if the type is validator or auditor.
	if r.requireGroup(userType) {
		valid, err := r.isValidGroup(group)
		if err != nil {
			return err
		}

		if !valid {
			return errors.New("Invalid type " + userType)

		}
	}

	return nil
}

// registerUserID registers a new user and its enrollmentID, role and state
func (r *Register) registerUserID(id string, userType string, group string, attributes []idp.Attribute, opt ...string) (string, error) {
	log.Debugf("Registering user id: %s\n", id)

	var tok string
	if len(opt) > 0 && len(opt[0]) > 0 {
		tok = opt[0]
	} else {
		tok = util.RandomString(12)
	}

	insert := spi.UserInfo{
		Name:       id,
		Pass:       tok,
		Type:       userType,
		Group:      group,
		Attributes: attributes,
	}

	_, err := userRegistry.GetUser(id, nil)
	if err == nil {
		log.Error("User is already registered")
		return "", cop.NewError(cop.RegisteringUserError, "User is already registered")
	}

	err = userRegistry.InsertUser(insert)
	if err != nil {
		return "", err
	}

	err = userRegistry.UpdateField(id, maxEnrollments, CFG.UsrReg.MaxEnrollments)
	if err != nil {
		return "", err
	}

	return tok, nil
}

func (r *Register) isValidGroup(group string) (bool, error) {
	log.Debug("Validating group: " + group)

	_, err := userRegistry.GetGroup(group)
	if err != nil {
		log.Error("Error occured getting group: ", err)
		return false, err
	}

	return true, nil
}

func (r *Register) requireGroup(userType string) bool {
	log.Debug("Check if group required for user type: ", userType)

	userType = strings.ToLower(userType)

	if userType == peer || userType == client {
		return true
	}

	return false
}

func (r *Register) canRegister(registrar string, userType string) error {
	log.Debugf("canRegister - Check to see if user %s can register", registrar)

	user, err := userRegistry.GetUser(registrar, nil)
	if err != nil {
		return fmt.Errorf("Registrar does not exist: %s", err)
	}

	var roles []string
	rolesStr := user.GetAttribute(registrarRoles)
	if rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	} else {
		roles = make([]string, 0)
	}
	if !util.StrContained(userType, roles) {
		return cop.NewError(cop.RegisteringUserError, "user %s may not register type %s", registrar, userType)
	}

	return nil
}
