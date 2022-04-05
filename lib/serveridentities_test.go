/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
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
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
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
		Name: "notregistrar",
		Type: "client",
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
	if assert.Error(t, err, "Should have failed, caller is not a registrar") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}

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
		Name: "notregistrar",
		Type: "client",
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
	if assert.Error(t, err, "Should have failed, caller is not a registrar") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}

	_, err = admin.RemoveIdentity(remReq)
	assert.NoError(t, err, "Failed to remove user")

	registry := srv.CA.registry
	_, err = registry.GetUser(remReq.ID, nil)
	assert.Error(t, err, "User should not exist")

	certs, err := srv.CA.certDBAccessor.GetCertificatesByID(remReq.ID)
	if certs[0].Status != "revoked" || certs[0].Reason != ocsp.CessationOfOperation {
		t.Error("Failed to correctly revoke certificate for an identity whose affiliation was removed")
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
				Name:  attr.Roles,
				Value: "client,orderer,peer",
			},
			api.Attribute{
				Name:  attr.DelegateRoles,
				Value: "client,orderer,peer",
			},
			api.Attribute{
				Name:  attr.Revoker,
				Value: "true",
			},
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "foo, custom.*, hf.Registrar.Roles, hf.Registrar.DelegateRoles, hf.Revoker, hf.Registrar.Attributes",
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
			api.Attribute{
				Name:  attr.Roles,
				Value: "client,peer",
			},
		},
	})
	util.FatalError(t, err, "Failed to register user 'testuser2'")

	registry := srv.CA.registry

	modifyTypeAndAffiliation(t, registry, admin2, admin3)
	modifyFixedValueAttrs(t, admin)
	modifyAttributes(t, registry, admin, admin3)
	modifySecretAndMaxEnroll(t, registry, admin)

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

	modReq := &api.ModifyIdentityRequest{
		ID: "testuser2",
	}
	_, err = notregistrar.ModifyIdentity(modReq)
	if assert.Error(t, err, "Should have failed, caller is not a registrar") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}
}

func modifyTypeAndAffiliation(t *testing.T, registry user.Registry, admin2, admin3 *Identity) {
	modReq := &api.ModifyIdentityRequest{
		ID: "testuser",
	}

	// Should error, caller is not part of the right affiliation
	_, err := admin2.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not part of the right affiliation")

	// Should error, caller is not allowed to act on type
	modReq.ID = "testuser2"
	modReq.Type = "user"
	_, err = admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to act on type")

	// Should error, caller is not allowed to change to the requested affiliation.
	// Caller is part of the 'hyperledger' affiliation
	modReq.ID = "testuser2"
	modReq.Affiliation = "org2"
	_, err = admin2.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to change to the requested affiliation")

	// Check that updating identity's type also updates the corresponding attribute 'hf.Type'
	modReq.Type = "orderer"
	_, err = admin3.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	user, err := registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	userTypeAttr, err := user.GetAttribute("hf.Type")
	assert.NoError(t, err, "Failed to get attribute")

	if userTypeAttr.GetValue() != "orderer" {
		t.Error("Failed to update 'hf.Type' attribute when identity's type was updated")
	}

	userAffAttr, err := user.GetAttribute("hf.Affiliation")
	assert.NoError(t, err, "Failed to get attribute 'hf.Affiliation'")
	if userAffAttr.Value != "org2" {
		t.Errorf("Failed to correctly update 'hf.Affiliation' when affiliation of identity was modified to 'org2'")
	}

	modReq.Affiliation = "hyperledger.fake"
	_, err = admin2.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, affiliation does not exist")
}

func modifyFixedValueAttrs(t *testing.T, admin *Identity) {
	modReq := &api.ModifyIdentityRequest{
		ID: "testuser2",
	}

	modReq.Attributes = []api.Attribute{api.Attribute{
		Name:  attr.EnrollmentID,
		Value: "nottestuser2",
	}}
	_, err := admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to register/modify 'hf.Type' attribute")

	modReq.Attributes = []api.Attribute{api.Attribute{
		Name:  attr.Type,
		Value: "peer",
	}}
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to register/modify 'hf.Type' attribute")

	modReq.Attributes = []api.Attribute{api.Attribute{
		Name:  attr.Affiliation,
		Value: "org1",
	}}
	_, err = admin.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to register/modify 'hf.Type' attribute")
}

func modifyAttributes(t *testing.T, registry user.Registry, admin, admin3 *Identity) {
	modReq := &api.ModifyIdentityRequest{
		ID: "testuser2",
	}

	// Should error, caller is not allowed to register this attribute. Caller does not posses hf.IntermediateCA.
	modReq.Attributes = []api.Attribute{api.Attribute{
		Name:  "hf.IntermediateCA",
		Value: "true",
	}}
	_, err := admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller does not own this attribute and thus is not allowed to register this attribute")

	// Should error, caller is not allowed to register attribute 'hf.Registrar.DeletegateRoles' with a value that
	// is not equal to or a subset of 'hf.Registrar.Roles'. In this case: client,peer
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  attr.DelegateRoles,
			Value: "client,peer,orderer",
		},
	}
	_, err = admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to register attribute 'hf.Registrar.DeletegateRoles' with a value that is not equal to or a subset of 'hf.Registrar.Roles'")

	// Caller is allowed to register attribute 'hf.Registrar.DeletegateRoles' with a value that
	// equal to or a subset of 'hf.Registrar.Roles'. In this case: client,peer,orderer
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  attr.Roles,
			Value: "client,peer,orderer",
		},
		api.Attribute{
			Name:  attr.DelegateRoles,
			Value: "client,peer,orderer",
		},
	}
	_, err = admin3.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to register attribute 'hf.Registrar.DeletegateRoles' with a value that is equal to or a subset of 'hf.Registrar.Roles'")

	// Should error, caller is not allowed to register attribute 'hf.Registrar.Attribute' with a value of 'hf.Revoker'. Identity being modified does not posses
	// the attribute 'hf.Revoker'
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  attr.RegistrarAttr,
			Value: "hf.Revoker",
		},
	}
	_, err = admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is not allowed to register attribute 'hf.Registrar.Attribute' with a value of 'hf.Revoker'")

	// Should not error, caller is  allowed to register attribute 'hf.Registrar.Attribute' with a value of 'hf.Revoker'. Identity being modified does posses
	// the attribute 'hf.Revoker'
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  attr.Revoker,
			Value: "true",
		},
		api.Attribute{
			Name:  attr.RegistrarAttr,
			Value: "hf.Revoker",
		},
	}
	_, err = admin3.ModifyIdentity(modReq)
	assert.NoError(t, err, "Should not have failed, caller is allowed to register attribute 'hf.Registrar.Attribute' with a value of 'hf.Revoker'")

	// Should error, caller is not allowed to register attribute 'hf.Registrar.Attribute' with greater
	// registering abilities than caller
	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  "foo",
			Value: "bar2",
		},
		api.Attribute{
			Name:  attr.RegistrarAttr,
			Value: "foo,custom",
		},
	}
	_, err = admin3.ModifyIdentity(modReq)
	assert.Error(t, err, "Should have failed, caller is allowed to register attribute 'hf.Registrar.Attribute' with greater registering abilities than caller")

	modReq.Attributes = []api.Attribute{
		api.Attribute{
			Name:  "foo",
			Value: "bar2",
		},
		api.Attribute{
			Name:  attr.RegistrarAttr,
			Value: "foo,custom.attr",
		},
	}
	_, err = admin3.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity, unable to register attributes")

	user, err := registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	attr, err := user.GetAttribute("foo")
	assert.NoError(t, err, "Failed to get attribute 'foo'")
	if attr.Value != "bar2" {
		t.Errorf("Failed to correctly modify existing attribute for user 'testuser2'")
	}
	attr, err = user.GetAttribute("hf.Revoker")
	assert.NoError(t, err, "Failed to get attribute 'hf.Revoker'")
	if attr.Value != "true" {
		t.Errorf("Failed to correctly add a new attribute for user 'testuser2'")
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

	user, err = registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	_, err = user.GetAttribute("foo")
	assert.Error(t, err, "Should have failed to get attribute 'foo', should have been deleted")
}

func modifySecretAndMaxEnroll(t *testing.T, registry user.Registry, admin *Identity) {
	modReq := &api.ModifyIdentityRequest{
		ID: "testuser2",
	}

	modReq.MaxEnrollments = -2
	modReq.Secret = "password"
	_, err := admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	user, err := registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	maxEnroll := user.(*cadbuser.Impl).Info.MaxEnrollments
	if maxEnroll != 0 {
		t.Error("Failed to correctly modify max enrollments for user 'testuser2'")
	}

	userAff := cadbuser.GetAffiliation(user)
	if userAff != "org2" {
		t.Errorf("Failed to correctly modify affiliation for user 'testuser2'")
	}

	modReq.MaxEnrollments = 5
	modReq.Affiliation = "."
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	user, err = registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "Failed to get user 'testuser2'")

	maxEnroll = user.(*cadbuser.Impl).Info.MaxEnrollments
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

func TestBootstrapUserAddingRoles(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)
	os.RemoveAll("../testdata/msp")
	defer os.RemoveAll("../testdata/msp")

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

	// Bootstrap user with '*' for hf.Registrar.Roles should be able to register any type
	_, err = admin.AddIdentity(&api.AddIdentityRequest{
		ID:   "testuser",
		Type: "newType",
	})
	assert.NoError(t, err, "Bootstrap user with '*' for hf.Registrar.Roles should be able to register any type")

	// Bootstrap user with '*' for hf.Registrar.Roles should be able to register any value for hf.Registrar.Roles
	_, err = admin.AddIdentity(&api.AddIdentityRequest{
		ID:   "testuser2",
		Type: "client",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer,client,user,orderer,newType",
			},
		},
	})
	assert.NoError(t, err, "Bootstrap user with '*' for hf.Registrar.Roles should be able to register any value for hf.Registrar.Roles")

	// Bootstrap user should be able to register any value for hf.Registrar.Roles, but not be able to specify '*' for
	// hf.Registrar.DelegateRoles if hf.Registrar.Roles is not a '*'
	_, err = admin.AddIdentity(&api.AddIdentityRequest{
		ID:   "testuser2",
		Type: "client",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer,client,user,orderer,newType",
			},
			api.Attribute{
				Name:  "hf.Registrar.DelegateRoles",
				Value: "*",
			},
		},
	})
	assert.Error(t, err, "Bootstrap user should be able to register any value for hf.Registrar.Roles, but not be able to specify '*' for hf.Registrar.DelegateRoles if hf.Registrar.Roles is not a '*'")

	// Bootstrap should fail to register hf.Registrar.DelegateRoles without giving hf.Registrar.Roles attribute to the identity being registered
	_, err = admin.AddIdentity(&api.AddIdentityRequest{
		ID:   "testuser3",
		Type: "client",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.DelegateRoles",
				Value: "peer,client,user,orderer,newType",
			},
		},
	})
	assert.Error(t, err, "Should fail to register hf.Registrar.DelegateRoles without having hf.Registrar.Roles")

	// Bootstrap should be able to register '*' for hf.Registrar.Roles and provide any value for hf.Registrar.DelegateRoles
	_, err = admin.AddIdentity(&api.AddIdentityRequest{
		ID:   "testuser3",
		Type: "client",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "*",
			},
			api.Attribute{
				Name:  "hf.Registrar.DelegateRoles",
				Value: "peer,client,user,orderer,newType",
			},
		},
	})
	assert.NoError(t, err, "Bootstrap should be able to register star for hf.Registrar.Roles and provide any value for hf.Registrar.DelegateRoles")

	// Bootstrap user should be able to register '*' for hf.Registrar.Roles and hf.Registrar.DelegateRoles
	_, err = admin.AddIdentity(&api.AddIdentityRequest{
		ID:   "testuser4",
		Type: "client",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "*",
			},
			api.Attribute{
				Name:  "hf.Registrar.DelegateRoles",
				Value: "*",
			},
		},
	})
	assert.NoError(t, err, "Bootstrap user should be able to register '*' for hf.Registrar.Roles and hf.Registrar.DelegateRoles")
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
