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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/cli"
	"github.com/hyperledger/fabric-ca/api"
)

type Admin struct {
	Name       string
	Pass       []byte
	Type       string
	Group      string
	Attributes []api.Attribute
}

var (
	NotRegistrar = Admin{Name: "testUser2", Pass: []byte("pass"), Type: "User", Group: "bank_b", Attributes: []api.Attribute{api.Attribute{Name: "role", Value: "client"}}}
	Registrar    = Admin{Name: "admin", Pass: []byte("adminpw"), Type: "User", Group: "bank_a", Attributes: []api.Attribute{api.Attribute{Name: "hf.Registrar.DelegateRoles", Value: "client,user,auditor"}}}
	testUser     = api.RegistrationRequest{Name: "testUser1", Type: "user", Group: "bank_a", Attributes: []api.Attribute{api.Attribute{Name: "test", Value: "testValue"}}}
	testAuditor  = api.RegistrationRequest{Name: "testAuditor", Type: "Auditor", Attributes: []api.Attribute{api.Attribute{Name: "role", Value: "auditor"}}}
	testClient1  = api.RegistrationRequest{Name: "testClient1", Type: "Client", Group: "bank_a", Attributes: []api.Attribute{api.Attribute{Name: "test", Value: "testValue"}}}
	testBogus    = api.RegistrationRequest{Name: "testBogus", Type: "Bogus", Group: "bank_b", Attributes: []api.Attribute{api.Attribute{Name: "test", Value: "testValue"}}}
	testEnroll   = api.RegistrationRequest{Name: "testEnroll", Type: "User", Group: "bank_a", Attributes: []api.Attribute{api.Attribute{Name: "test", Value: "testValue"}}}
)

const (
	regPath = "/tmp/registertest"
)

func prepRegister() error {
	if _, err := os.Stat(regPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(regPath, 0755)
		}
	} else {
		os.RemoveAll(regPath)
		os.MkdirAll(regPath, 0755)
	}
	var err error

	cfg := new(cli.Config)
	cfg.ConfigFile = "../../testdata/testconfig.json"
	configInit(cfg)

	regCFG := CFG
	homeDir = regPath
	datasource := filepath.Join(homeDir, "fabric-ca.db")
	regCFG.DataSource = datasource

	err = InitUserRegistry(regCFG)
	if err != nil {
		return err
	}

	return nil
}

func bootstrapUsers() error {
	r := NewRegisterUser()
	if r == nil {
		return errors.New("Failed to get register object")
	}
	r.RegisterUser(Registrar.Name, Registrar.Type, Registrar.Group, Registrar.Attributes, "", string(Registrar.Pass))

	r.RegisterUser(NotRegistrar.Name, NotRegistrar.Type, NotRegistrar.Group, NotRegistrar.Attributes, "", string(NotRegistrar.Pass))

	return nil
}

func registerUser(registrar Admin, user *api.RegistrationRequest) (string, error) {
	r := NewRegisterUser()

	tok, err := r.RegisterUser(user.Name, user.Type, user.Group, user.Attributes, registrar.Name)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func TestAll_Register(t *testing.T) {
	err := prepRegister()
	if err != nil {
		t.Fatal("Failed to bootstrap database")
	}

	testRegisterUser(t)
	testRegisterDuplicateUser(t)
	testRegisterAuditor(t)
	testRegisterUserNonRegistrar(t)
	testRegisterUserBogus(t)
	testRegisterUserClient(t)

	os.RemoveAll(regPath)
}

func testRegisterUser(t *testing.T) {
	_, err := registerUser(Registrar, &testUser)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func testRegisterDuplicateUser(t *testing.T) {
	_, err := registerUser(Registrar, &testUser)

	if err == nil {
		t.Fatal("Expected an error when registering the same user twice")
	}

}

func testRegisterAuditor(t *testing.T) {

	_, err := registerUser(Registrar, &testAuditor)

	if err != nil {
		t.Fatal(err.Error())
	}
}

func testRegisterUserNonRegistrar(t *testing.T) {

	//testUser has no registrar metadata
	_, err := registerUser(NotRegistrar, &testUser)

	if err == nil {
		t.Fatal("User without registrar metadata should not be able to register a new user")
	}
}

func testRegisterUserBogus(t *testing.T) {

	_, err := registerUser(Registrar, &testBogus)

	if err == nil {
		t.Fatal("User should not be able to register a bogus type")
	}
}

//testAdmin should be able to register testClient1 since testAdmin's
//delegateRoles field contains the value "client"
func testRegisterUserClient(t *testing.T) {

	_, err := registerUser(Registrar, &testClient1)

	if err != nil {
		t.Error(err.Error())
	}
}
