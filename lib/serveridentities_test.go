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
	"path/filepath"
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

func TestDynamicAddIdentity(t *testing.T) {
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

	regResp, err := admin.Register(&api.RegistrationRequest{
		Name:        "notregistrar",
		Type:        "client",
		Affiliation: "org2",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "notregistrar",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'notregistrar'")

	notregistrar := resp.Identity

	addReq := &api.AddIdentityRequest{}
	_, err = admin.AddIdentity(addReq)
	assert.Error(t, err, "Should have failed, no name specified in request")

	modReq := &api.ModifyIdentityRequest{}
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, no name specified in request")

	addReq.ID = "testuser"
	addReq.Type = "client"
	addReq.Affiliation = "org2"
	_, err = notregistrar.AddIdentity(addReq)
	assert.Error(t, err, "Should have failed to add identity, caller is not a registrar")

	_, err = admin.AddIdentity(addReq)
	assert.NoError(t, err, "Failed to add identity")
}

func TestDynamicRemoveIdentity(t *testing.T) {
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

	// Register and enroll a user that is not a registrar
	regResp, err := admin.Register(&api.RegistrationRequest{
		Name:        "notregistrar",
		Type:        "client",
		Affiliation: "org2",
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "notregistrar",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'notregistrar'")

	notregistrar := resp.Identity

	// Register and enroll a registrar that is has limited ability
	// to act on identities
	regResp, err = admin.Register(&api.RegistrationRequest{
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
	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")
	admin2 := resp.Identity

	// Registers users that will be removed
	regResp, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Type:        "client",
		Affiliation: "org2",
	})

	regResp, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Type:        "peer",
		Affiliation: "hyperledger",
	})
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "testuser2",
		Secret: regResp.Secret,
	})
	util.FatalError(t, err, "Failed to enroll user 'testuser2'")

	remReq := &api.RemoveIdentityRequest{}
	remReq.ID = "testuser"
	_, err = admin.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identities; identity removal is not enabled on server")

	srv.CA.Config.Cfg.Identities.AllowRemove = true

	remReq.ID = ""
	_, err = admin.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed; no name specified in request")

	remReq.ID = "testuser"
	_, err = admin2.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identity; caller does not have the right type")

	remReq.ID = "testuser2"
	_, err = admin2.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identity; caller does not have the right affiliation")

	_, err = notregistrar.RemoveIdentity(remReq)
	assert.Error(t, err, "Should have failed to remove identity; caller is not a registrar")

	_, err = admin.RemoveIdentity(remReq)
	assert.NoError(t, err, "Failed to remove user")

	registry := srv.CA.registry
	_, err = registry.GetUser(remReq.ID, nil)
	assert.Error(t, err, "User should not exist")

	certs, err := srv.CA.certDBAccessor.GetCertificatesByID(remReq.ID)
	if len(certs) != 0 {
		t.Errorf("Failed to delete certificates for a removed identity '%s'", remReq.ID)
	}
}

func TestDynamicModifyIdentity(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "hyperledger")
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

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin2'")

	admin2 := resp.Identity

	_, err = admin.Register(&api.RegistrationRequest{
		Name:           "admin3",
		Type:           "client",
		Secret:         "admin3pw",
		MaxEnrollments: 10,
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "client",
			},
			api.Attribute{
				Name:  "hf.Registrar.Attributes",
				Value: "hf.Revoker, foo",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin3",
		Secret: "admin3pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin3'")

	admin3 := resp.Identity

	_, err = admin.Register(&api.RegistrationRequest{
		Name:           "testuser",
		Type:           "peer",
		Secret:         "testuserpw",
		MaxEnrollments: 10,
		Affiliation:    "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "foo",
				Value: "bar",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")

	_, err = admin.Register(&api.RegistrationRequest{
		Name:           "testuser2",
		Type:           "client",
		Secret:         "testuserpw",
		MaxEnrollments: 10,
		Affiliation:    "hyperledger",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "foo",
				Value: "bar",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'testuser2'")

	modReq := &api.ModifyIdentityRequest{}

	modReq.ID = "testuser"
	modReq.Type = "client"
	// Should error, caller is not part of the right affiliation
	_, err = admin2.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not part of the right affiliation")

	// Should error, caller is not allowed to act on type
	_, err = admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to act on type")

	// Should error, caller is not allowed to change to the requested affiliation.
	// Caller is part of the 'hyperledger' affiliation
	modReq.ID = "testuser2"
	modReq.Affiliation = "org2"
	_, err = admin2.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not to change to the requested affiliation")

	modReq.Affiliation = "hyperledger.fake"
	_, err = admin2.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, affiliation does not exist")

	// Should error, caller is not allowed to change to the requested type.
	// Caller can only issue type 'client'
	modReq.ID = "testuser2"
	modReq.Type = "peer"
	modReq.Affiliation = "org2"
	_, err = admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to change to the requested type")

	// Should error, caller is not allowed to register this attribute
	modReq.Type = "client"
	modReq.Attributes = []api.Attribute{api.Attribute{
		Name:  "hf.IntermediateCA",
		Value: "true",
	}}
	_, err = admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to register this attribute")

	// Should not error, caller is allowed to register this attribute
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  "hf.Type",
			Value: "client",
		},
	}
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, can't modify a reserved attribute")

	// Should not error, caller is allowed to register this attribute
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  "hf.Revoker",
			Value: "true",
		},
		api.Attribute{
			Name:  "foo",
			Value: "bar2",
		},
	}
	_, err = admin3.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to register these attribute")

	modReq.MaxEnrollments = -2
	modReq.Secret = "password"
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	user, err := srv.CA.registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	maxEnroll := user.(*DBUser).UserInfo.MaxEnrollments
	if maxEnroll != 0 {
		t.Error("Failed to correctly modify max enrollments for user 'testuser2'")
	}

	userAff := strings.Join(user.GetAffiliationPath(), ".")
	if userAff != "org2" {
		t.Errorf("Failed to correctly modify affiliation for user 'testuser2'")
	}

	attr, err := user.GetAttribute("foo")
	assert.NoError(t, err, "Failed to get attribute 'foo'")
	if attr.Value != "bar2" {
		t.Errorf("Failed to correctly modify existing attribute for user 'testuser2'")
	}
	attr, err = user.GetAttribute("hf.Revoker")
	assert.NoError(t, err, "Failed to get attribute 'foo'")
	if attr.Value != "true" {
		t.Errorf("Failed to correctly add a new attribute for user 'testuser2'")
	}
	attr, err = user.GetAttribute("hf.Type")
	assert.NoError(t, err, "Failed to get attribute 'foo'")
	if attr.Value != "client" {
		t.Errorf("Failed to correctly update 'hf.Type' when type of identity was modified to 'client'")
	}
	attr, err = user.GetAttribute("hf.Affiliation")
	assert.NoError(t, err, "Failed to get attribute 'foo'")
	if attr.Value != "org2" {
		t.Errorf("Failed to correctly update 'hf.Affiliation' when affiliation of identity was modified to 'org2'")
	}

	// Delete attribute 'foo'
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  "foo",
			Value: "",
		},
	}
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	user, err = srv.CA.registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	_, err = user.GetAttribute("foo")
	assert.Error(t, err, "Should have failed to get attribute 'foo', should have been deleted")

	modReq.MaxEnrollments = 5
	modReq.Affiliation = "."
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	user, err = srv.CA.registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	maxEnroll = user.(*DBUser).UserInfo.MaxEnrollments
	if maxEnroll != 5 {
		t.Error("Failed to correctly modify max enrollments for user 'testuser2'")
	}

	userAff = strings.Join(user.GetAffiliationPath(), ".")
	if userAff != "" {
		t.Errorf("Failed to correctly modify affiliation to root affiliation for user 'testuser2'")
	}

}

func TestDynamicWithMultCA(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)
	os.RemoveAll("../testdata/msp")
	defer os.RemoveAll("../testdata/msp")
	defer cleanMultiCADir(t)

	var err error

	srv := TestGetRootServer(t)
	srv.Config.CAfiles = []string{"../../testdata/ca/rootca/ca1/fabric-ca-server-config.yaml", "../../testdata/ca/rootca/ca2/fabric-ca-server-config.yaml"}
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		CAName: "rootca2",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	addReq := &api.AddIdentityRequest{}
	addReq.ID = "testuser"
	addReq.Type = "client"
	addReq.Affiliation = "org2"
	addReq.CAName = "rootca2"
	resp2, err := admin.AddIdentity(addReq)
	assert.NoError(t, err, "Failed to add identity")

	if resp2.CAName != "rootca2" {
		t.Error("Failed to get response back from the right ca")
	}

	modReq := &api.ModifyIdentityRequest{}
	modReq.ID = "testuser"
	modReq.Type = "peer"
	modReq.CAName = "rootca2"
	resp2, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	if resp2.CAName != "rootca2" {
		t.Error("Failed to get response back from the right ca")
	}

	srv.caMap["rootca2"].Config.Cfg.Identities.AllowRemove = true

	remReq := &api.RemoveIdentityRequest{}
	remReq.ID = "testuser"
	remReq.CAName = "rootca2"
	resp2, err = admin.RemoveIdentity(remReq)
	assert.NoError(t, err, "Failed to remove identity")

	if resp2.CAName != "rootca2" {
		t.Error("Failed to get response back from the right ca")
	}

}

func cleanMultiCADir(t *testing.T) {
	var err error
	caFolder := "../testdata/ca"
	toplevelFolders := []string{"rootca"}
	nestedFolders := []string{"ca1", "ca2"}
	removeFiles := []string{"ca-cert.pem", "ca-key.pem", "fabric-ca-server.db", "fabric-ca2-server.db", "ca-chain.pem"}

	for _, topFolder := range toplevelFolders {
		for _, nestedFolder := range nestedFolders {
			path := filepath.Join(caFolder, topFolder, nestedFolder)
			for _, file := range removeFiles {
				err = os.RemoveAll(filepath.Join(path, file))
				if err != nil {
					t.Errorf("RemoveAll failed: %s", err)
				}
			}
			err = os.RemoveAll(filepath.Join(path, "msp"))
			if err != nil {
				t.Errorf("RemoveAll failed: %s", err)
			}
		}
	}
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
