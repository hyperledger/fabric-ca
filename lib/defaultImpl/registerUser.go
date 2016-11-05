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

package defaultImpl

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

type Register struct {
	DB         *sqlx.DB
	DbAccessor *Accessor
}

var (
	mutex = &sync.RWMutex{}
)

const (
	roles       string = "roles"
	peer        string = "peer"
	client      string = "client"
	isRegistrar string = "hf.Registrar.DelegateRoles"
)

func NewRegisterUser() *Register {
	r := new(Register)
	cfg := config.CFG
	home := cfg.Home
	dataSource := filepath.Join(home, cfg.DataSource)
	r.DB, _ = util.GetDB(cfg.DBdriver, dataSource)
	r.DbAccessor = NewAccessor(r.DB)
	return r
}

func (r *Register) RegisterUser(id string, group string, metadata string, registrar string) (string, error) {
	log.Debugf("Received request to register user with id: %s, group: %s, metadata: %s, registrar: %s\n",
		id, group, metadata, registrar)

	var attributes []cop.Attribute
	if err := json.Unmarshal([]byte(metadata), &attributes); err != nil {
		return "", err
	}

	var enrollID, tok string
	var err error

	if registrar != "" {
		// Check the permissions of member named 'registrar' to perform this registration
		err = r.canRegister(registrar, attributes)
		if err != nil {
			return "", err
		}
	}

	enrollID, err = r.validateAndGenerateEnrollID(id, group, attributes)
	if err != nil {
		return "", err
	}
	tok, err = r.registerUserWithEnrollID(id, enrollID, metadata)
	if err != nil {
		return "", err
	}

	return tok, nil
}

// func (r *Register) validateAndGenerateEnrollID(id, group string, attr []*pb.Attribute) (string, error) {
func (r *Register) validateAndGenerateEnrollID(id, group string, attr []cop.Attribute) (string, error) {
	log.Debug("validateAndGenerateEnrollID")
	// Check whether the group is required for the current user.

	// group is required if the role is client or peer.
	// group is not required if the role is validator or auditor.
	if r.requireGroup(attr) {
		valid, err := r.isValidGroup(group)
		if err != nil {
			return "", err
		}

		if !valid {
			return "", errors.New("Invalid group " + group)

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
func (r *Register) registerUserWithEnrollID(id string, enrollID string, metadata string) (string, error) {
	log.Debug("registerUserWithEnrollID")
	mutex.Lock()
	defer mutex.Unlock()

	log.Debugf("Registering user id: %s, enrollID: %s\n", id, enrollID)

	var tok string
	tok = util.RandomString(12)

	insert := cop.UserRecord{
		ID:           id,
		EnrollmentID: enrollID,
		Token:        tok,
		Metadata:     metadata,
		State:        0,
	}

	_, err := r.DbAccessor.GetUser(id)
	if err == nil {
		log.Error("User is already registered")
		return "", errors.New("User is already registered")
	}
	err = r.DbAccessor.InsertUser(insert)
	if err != nil {
		return "", err
	}

	return tok, nil
}

func (r *Register) isValidGroup(group string) (bool, error) {
	log.Debug("Validating group: " + group)
	// Check cop.yaml to see if group is valid

	_, _, err := r.DbAccessor.GetGroup(group)
	if err != nil {
		return false, nil
	}

	return true, nil
}

// func (r *Register) requireGroup(attributes []*pb.Attribute) bool {
func (r *Register) requireGroup(attributes []cop.Attribute) bool {
	log.Debug("requireGroup, attributes: ", attributes)

	for _, attr := range attributes {
		values := attr.Value
		if strings.Contains(strings.ToLower(attr.Name), roles) {
			for _, value := range values {
				val := strings.ToLower(value)
				if val == peer || val == client {
					return true
				}
			}
		}
	}

	return false
}

// func (r *Register) canRegister(registrar string, attributes []*pb.Attribute) errors {
func (r *Register) canRegister(registrar string, attributes []cop.Attribute) error {
	log.Debugf("canRegister - Check to see if user %s can register", registrar)

	check, err := r.isRegistrar(registrar)
	if err != nil {
		return errors.New("Can't Register: " + err.Error())
	}

	if check != true {
		return errors.New("Can't Register: " + err.Error())
	}

	registrarUser, _ := r.DbAccessor.GetUser(registrar)

	var metaData []cop.Attribute
	json.Unmarshal([]byte(registrarUser.Metadata), &metaData)

	for _, attr := range attributes {
		if strings.Contains(strings.ToLower(attr.Name), roles) {
			userRoles := attr.Value
			for _, rAttr := range metaData {
				if strings.Contains(strings.ToLower(attr.Name), roles) {
					registrarRoles := rAttr.Value
					for _, role := range userRoles {
						if !util.StrContained(role, registrarRoles) {
							return errors.New("user " + registrar + " may not register " + role)
						}
					}
				}
			}
		}
	}
	return nil
}

func (r *Register) isRegistrar(registrar string) (bool, error) {
	log.Debugf("isRegistrar - Check if specified registrar (%s) has appropriate permissions", registrar)

	checkUser, err := r.DbAccessor.GetUser(registrar)
	if err != nil {
		return false, errors.New("Registrar does not exist")
	}
	var attributes []cop.Attribute
	json.Unmarshal([]byte(checkUser.Metadata), &attributes)

	for _, attr := range attributes {
		if attr.Name == isRegistrar && attr.Value != nil {
			return true, nil
		}
	}

	return false, errors.New("Is not registrar")
}
