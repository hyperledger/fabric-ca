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
	"os"
	"testing"

	"github.com/cloudflare/cfssl/cli"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

type Admin struct {
	User       string
	Pass       []byte
	Group      string
	Attributes []cop.Attribute
}

var (
	NotRegistrar = Admin{User: "testUser2", Group: "bank_b", Attributes: []cop.Attribute{cop.Attribute{Name: "role", Value: []string{"client"}}}}
	Registrar    = Admin{User: "admin", Pass: []byte("Xurw3yU9zI0l"), Group: "bank_a", Attributes: []cop.Attribute{cop.Attribute{Name: "hf.Registrar.DelegateRoles", Value: []string{"client", "validator", "auditor"}}}}
	testUser     = cop.RegisterRequest{User: "testUser", Group: "bank_a", Attributes: []cop.Attribute{cop.Attribute{Name: "role", Value: []string{"client"}}}}
	testAuditor  = cop.RegisterRequest{User: "testAuditor", Attributes: []cop.Attribute{cop.Attribute{Name: "role", Value: []string{"auditor"}}}}
	testClient1  = cop.RegisterRequest{User: "testClient1", Group: "bank_a", Attributes: []cop.Attribute{cop.Attribute{Name: "role", Value: []string{"client"}}}}
	testPeer     = cop.RegisterRequest{User: "testPeer", Group: "bank_b", Attributes: []cop.Attribute{cop.Attribute{Name: "Roles", Value: []string{"peer"}}}}
	testEnroll   = cop.RegisterRequest{User: "testEnroll", Group: "bank_a", Attributes: []cop.Attribute{cop.Attribute{Name: "role", Value: []string{"client"}}}}
)

const (
	regPath = "/tmp/hyperledger/registerTest"
)

func prepRegister() {
	os.MkdirAll(regPath, 0755)
	cfg := new(cli.Config)
	cfg.ConfigFile = "../../testdata/cop.json"
	cfg.DBConfigFile = "../../testdata/registerTest.json"
	config.Init(cfg)

	regCFG := config.CFG
	db, _ := util.CreateTables(regCFG)
	bootstrapGroups(db)
	bootstrapRegistrar(Registrar)
}

// func getRegUser() *Register {
// 	r := NewRegisterUser()
// 	return r
// }

func bootstrapGroups(db *sqlx.DB) error {
	b := new(Bootstrap)
	b.PopulateGroupsTable(db)
	return nil
}

func bootstrapRegistrar(registrar Admin) error {
	r := NewRegisterUser()
	if r == nil {
		return errors.New("Failed to get register object")
	}
	metaDataBytes, err := json.Marshal(registrar.Attributes)
	if err != nil {
		return err
	}
	metaData := string(metaDataBytes)
	r.RegisterUser(registrar.User, registrar.Group, metaData, "")

	return nil
}

func registerUser(registrar Admin, user *cop.RegisterRequest) (string, error) {
	r := NewRegisterUser()
	metaDataBytes, err := json.Marshal(user.Attributes)
	if err != nil {
		return "", err
	}
	metaData := string(metaDataBytes)
	user.CallerID = registrar.User
	tok, err := r.RegisterUser(user.User, user.Group, metaData, user.CallerID)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func TestAll_Register(t *testing.T) {
	prepRegister()

   /* Saad TODO: commenting out til working (Keith)
	testRegisterUser(t)
	testRegisterDuplicateUser(t)
	testRegisterAuditor(t)
	testRegisterUserNonRegistrar(t)
	testRegisterUserPeer(t)
	testRegisterUserClient(t)
   */

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

	if err.Error() != "User is already registered" {
		t.Fatalf("Expected error was not returned when registering user twice: [%s]", err.Error())
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
	t.Logf("Expected an error and indeed received: [%s]", err.Error())
}

func testRegisterUserPeer(t *testing.T) {

	_, err := registerUser(Registrar, &testPeer)

	if err == nil {
		t.Fatal("User without appropriate delegateRoles should not be able to register a new user")
	}
	t.Logf("Expected an error and indeed received: [%s]", err.Error())
}

//testAdmin should be able to register testClient1 since testAdmin's
//delegateRoles field contains the value "client"
func testRegisterUserClient(t *testing.T) {

	_, err := registerUser(Registrar, &testClient1)

	if err != nil {
		t.Error(err.Error())
	}
}
