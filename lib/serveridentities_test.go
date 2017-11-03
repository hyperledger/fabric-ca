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
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetAllIDs(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	// Register several users
	admin := resp.Identity
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "admin2",
		Secret:      "admin2pw",
		Type:        "peer",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'admin2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Type:        "client",
		Affiliation: "hyperledger",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Type:        "peer",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser3",
		Type:        "peer",
		Affiliation: "org2.dept1",
	})
	util.FatalError(t, err, "Failed to register user 'testuser2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser4",
		Type:        "client",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser3'")

	os.Setenv("FABRIC_CA_SERVER_MAX_IDS_PER_CHUNK", "2")
	// As bootstrap user that has all root permission, should get back all the users in the database
	result, err := captureOutput(admin.GetAllIdentities, "", IdentityDecoder)
	assert.NoError(t, err, "Failed to get all the appropriate identities")

	// Check to make sure that right users got returned
	expectedIDs := []string{"admin", "admin2", "testuser", "testuser2", "testuser3", "testuser4"}
	for _, id := range expectedIDs {
		if !strings.Contains(result, id) {
			t.Error("Failed to get all appropriate IDs")
		}
	}

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")

	admin2 := resp.Identity
	os.Unsetenv("FABRIC_CA_SERVER_MAX_IDS_PER_CHUNK")
	result, err = captureOutput(admin2.GetAllIdentities, "", IdentityDecoder)
	assert.NoError(t, err, "Failed to get all the appropriate identities")

	// Check to make sure that right users got returned
	expectedIDs = []string{"admin2", "testuser2", "testuser3"}
	for _, id := range expectedIDs {
		if !strings.Contains(result, id) {
			t.Error("Failed to get all appropriate IDs")
		}
	}

	regResp, err := admin.Register(&api.RegistrationRequest{
		Name: "notregistrar",
		Type: "client",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "notregistrar",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'notregistrar'")

	notregistrar := resp.Identity

	err = notregistrar.GetAllIdentities("", IdentityDecoder)
	if assert.Error(t, err, "Should have failed, caller is not a registrar") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}
}

func TestGetID(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	// Register several users
	admin := resp.Identity
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "admin2",
		Secret:      "admin2pw",
		Type:        "peer",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'admin2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Type:        "client",
		Affiliation: "hyperledger",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Type:        "peer",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser3",
		Type:        "peer",
		Affiliation: "org2.dept1",
	})
	util.FatalError(t, err, "Failed to register user 'testuser2'")
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser4",
		Type:        "client",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser3'")

	// admin has all root permissions and should be able to get any user
	_, err = admin.GetIdentity("testuser", "")
	assert.NoError(t, err, "Failed to get user")

	_, err = admin.GetIdentity("testuser3", "")
	assert.NoError(t, err, "Failed to get user")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")

	admin2 := resp.Identity

	_, err = admin2.GetIdentity("testuser3", "")
	assert.NoError(t, err, "Failed to get user")

	// 'admin2' with affiliation of 'org2' is not authorized to get 'testuser' with affiliation of 'hyperledger'
	_, err = admin2.GetIdentity("testuser", "")
	assert.Error(t, err, "'admin2' with affiliation of 'org2' is not authorized to get 'testuser' with affiliation of 'hyperledger'")

	// 'admin2' of type 'peer' is not authorized to get 'testuser4' of type 'client'
	_, err = admin2.GetIdentity("testuser4", "")
	assert.Error(t, err, "'admin2' of type 'peer' is not authorized to get 'testuser4' of type 'client'")

	regResp, err := admin.Register(&api.RegistrationRequest{
		Name: "notregistrar",
		Type: "client",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "notregistrar",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'notregistrar'")

	notregistrar := resp.Identity

	_, err = notregistrar.GetIdentity("testuser", "")
	if assert.Error(t, err, "Should have failed, caller is not a registrar") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}

}

func TestDynamicIdentity(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	addReq := &api.AddIdentityRequest{}
	_, err = admin.AddIdentity(addReq)
	assert.Error(t, err, "Should have failed, no name specified in request")

	modReq := &api.ModifyIdentityRequest{}
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, no name specified in request")

	remReq := &api.RemoveIdentityRequest{}
	_, err = admin.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed, no name specified in request")

	addReq.ID = "testuser"
	_, err = admin.AddIdentity(addReq)
	assert.Error(t, err, "Not yet implemented")

	modReq.ID = "testuser"
	modReq.Type = "peer"
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Not yet implemented")

	remReq.ID = "testuser"
	_, err = admin.RemoveIdentity(remReq)
	assert.Error(t, err, "Not yet implemented")
}

func captureOutput(f func(string, func(*json.Decoder) error) error, caname string, cb func(*json.Decoder) error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout = w
	err = f(caname, cb)
	if err != nil {
		return "", err
	}
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String(), nil
}
