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
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"

	cop "github.com/hyperledger/fabric-cop/api"
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

	attributes, _ := json.Marshal(req.Attributes)

	// Register User
	tok, err := reg.RegisterUser(req.User, req.Type, req.Group, string(attributes), req.CallerID)
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
	roles         string = "roles"
	peer          string = "peer"
	client        string = "client"
	delegateRoles string = "hf.Registrar.DelegateRoles"
)

// NewRegisterUser is a constructor
func NewRegisterUser() *Register {
	r := new(Register)
	r.cfg = CFG
	return r
}

// RegisterUser will register a user
func (r *Register) RegisterUser(id string, userType string, group string, metadata string, registrar string, opt ...string) (string, error) {
	log.Debugf("Received request to register user with id: %s, group: %s, metadata: %s, registrar: %s\n",
		id, group, metadata, registrar)

	var attributes []idp.Attribute
	if err := json.Unmarshal([]byte(metadata), &attributes); err != nil {
		return "", err
	}

	var enrollID, tok string
	var err error

	if registrar != "" {
		// Check the permissions of member named 'registrar' to perform this registration
		err = r.canRegister(registrar, userType)
		if err != nil {
			return "", err
		}
	}

	// enrollID, err = r.validateAndGenerateEnrollID(id, group, attributes)
	enrollID, err = r.validateAndGenerateEnrollID(id, userType, group)

	if err != nil {
		return "", err
	}
	tok, err = r.registerUserWithEnrollID(id, enrollID, userType, metadata, opt...)
	if err != nil {
		return "", err
	}

	return tok, nil
}

// func (r *Register) validateAndGenerateEnrollID(id, group string, attr []idp.Attribute) (string, error) {
func (r *Register) validateAndGenerateEnrollID(id string, userType string, group string) (string, error) {

	log.Debug("validateAndGenerateEnrollID")
	// Check whether the group is required for the current user.

	// group is required if the type is client or peer.
	// group is not required if the type is validator or auditor.
	if r.requireGroup(userType) {
		valid, err := r.isValidGroup(group)
		if err != nil {
			return "", err
		}

		if !valid {
			return "", errors.New("Invalid type " + userType)

		}

		return r.generateEnrollID(id, group)
	}

	return "", nil
}

func (r *Register) generateEnrollID(id string, group string) (string, error) {
	log.Debug("generateEnrollID")
	if id == "" || group == "" {
		return "", errors.New("Please provide all the input parameters, id and role")

	}

	if strings.Contains(id, "\\") || strings.Contains(group, "\\") {
		return "", errors.New("Do not include the escape character \\ as part of the values")
	}

	return id + "\\" + group, nil
}

// registerUserWithEnrollID registers a new user and its enrollmentID, role and state
func (r *Register) registerUserWithEnrollID(id string, enrollID string, userType string, metadata string, opt ...string) (string, error) {
	log.Debug("registerUserWithEnrollID")
	mutex.Lock()
	defer mutex.Unlock()

	log.Debugf("Registering user id: %s, enrollID: %s\n", id, enrollID)

	var tok string
	if len(opt) > 0 && len(opt[0]) > 0 {
		tok = opt[0]
	} else {
		tok = util.RandomString(12)
	}

	insert := cop.UserRecord{
		ID:           id,
		EnrollmentID: enrollID,
		Token:        tok,
		Type:         userType,
		Metadata:     metadata,
		State:        0,
	}

	_, err := r.cfg.DBAccessor.GetUser(id)
	if err == nil {
		log.Error("User is already registered")
		return "", errors.New("User is already registered")
	}
	err = r.cfg.DBAccessor.InsertUser(insert)
	if err != nil {
		return "", err
	}

	return tok, nil
}

func (r *Register) isValidGroup(group string) (bool, error) {
	log.Debug("Validating group: " + group)
	// Check cop.yaml to see if group is valid

	_, _, err := r.cfg.DBAccessor.GetGroup(group)
	if err != nil {
		log.Error("Error occured getting group: ", err)
		return false, err
	}

	return true, nil
}

func (r *Register) requireGroup(userType string) bool {
	log.Debug("requireGroup, userType: ", userType)

	userType = strings.ToLower(userType)

	if userType == peer || userType == client {
		return true
	}

	return false
}

func (r *Register) canRegister(registrar string, userType string) error {
	log.Debugf("canRegister - Check to see if user %s can register", registrar)

	check, err := r.isRegistrar(registrar)
	if err != nil {
		return errors.New("Can't Register: " + err.Error())
	}

	if check != true {
		return errors.New("Can't Register: " + err.Error())
	}

	registrarUser, _ := r.cfg.DBAccessor.GetUser(registrar)

	var metaData []idp.Attribute
	json.Unmarshal([]byte(registrarUser.Metadata), &metaData)

	for _, rAttr := range metaData {

		if strings.ToLower(rAttr.Name) == strings.ToLower(delegateRoles) {
			registrarRoles := strings.Split(rAttr.Value, ",")
			if !util.StrContained(userType, registrarRoles) {
				return errors.New("user " + registrar + " may not register type " + userType)
			}
		}
	}

	return nil
}

// Check if specified registrar has appropriate permissions
func (r *Register) isRegistrar(registrar string) (bool, error) {
	log.Debugf("isRegistrar - Check if specified registrar (%s) has appropriate permissions", registrar)

	checkUser, err := r.cfg.DBAccessor.GetUser(registrar)
	if err != nil {
		return false, errors.New("Registrar does not exist")
	}
	var attributes []idp.Attribute
	json.Unmarshal([]byte(checkUser.Metadata), &attributes)

	for _, attr := range attributes {
		if attr.Name == delegateRoles && attr.Value != "" {
			return true, nil
		}
	}

	log.Errorf("%s is not a registrar", registrar)
	return false, errors.New("Is not registrar")
}
