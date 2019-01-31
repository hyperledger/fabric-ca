/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func TestGetAllAffiliations(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")

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

	admin2 := resp.Identity

	getResp, err := admin.GetAllAffiliations("")
	assert.NoError(t, err, "Failed to get all affiliations")

	affiliations := []db.AffiliationRecord{}
	err = srv.CA.db.Select("", &affiliations, srv.CA.db.Rebind("SELECT * FROM affiliations"))
	if err != nil {
		t.Error("Failed to get all affiliations in database")
	}

	for _, aff := range affiliations {
		if !searchTree(getResp, aff.Name) {
			t.Error("Failed to get all appropriate affiliations")
		}
	}

	// admin2's affilations is "org2"
	getResp, err = admin2.GetAllAffiliations("")
	assert.NoError(t, err, "Failed to get all affiliations for admin2")

	if !searchTree(getResp, "org2") {
		t.Error("Failed to get all appropriate affiliations")
	}

	notAffMgr, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notAffMgr",
	})
	util.FatalError(t, err, "Failed to register a user that is not affiliation manager")

	_, err = notAffMgr.GetAllAffiliations("")
	if assert.Error(t, err, "Should have failed, as the caller does not have the attribute 'hf.AffiliationMgr'") {
		assert.Contains(t, err.Error(), "User does not have attribute 'hf.AffiliationMgr'")
	}

	err = srv.Stop()
	util.FatalError(t, err, "Failed to stop server")

	srv = TestGetRootServer(t)
	srv.CA.Config.Affiliations = nil
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client = getTestClient(7075)
	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")
	admin = resp.Identity

	getResp, err = admin.GetAllAffiliations("")
	util.ErrorContains(t, err, "16", "If no affiliations are configured, should throw an error")
}

func TestGetAffiliation(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
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

	admin2 := resp.Identity

	getAffResp, err := admin.GetAffiliation("org2", "")
	assert.NoError(t, err, "Failed to get requested affiliations")
	assert.Equal(t, "org2", getAffResp.Name)
	assert.Equal(t, "org2.dept1", getAffResp.Affiliations[0].Name)

	getAffResp, err = admin.GetAffiliation("org2.dept1", "")
	assert.NoError(t, err, "Failed to get requested affiliations")
	assert.Equal(t, "org2.dept1", getAffResp.Name)

	getAffResp, err = admin2.GetAffiliation("org1", "")
	assert.Error(t, err, "Should have failed, caller not authorized to get affiliation")

	getAffResp, err = admin2.GetAffiliation("org2.dept2", "")
	assert.Error(t, err, "Should have returned an error, requested affiliation does not exist")

	getAffResp, err = admin2.GetAffiliation("org2.dept1", "")
	assert.NoError(t, err, "Failed to get requested affiliation")

	notAffMgr, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notAffMgr",
	})
	util.FatalError(t, err, "Failed to register a user that is not affiliation manager")

	_, err = notAffMgr.GetAffiliation("org2", "")
	assert.Error(t, err, "Should have failed, as the caller does not have the attribute 'hf.AffiliationMgr'")
}

func TestDynamicAddAffiliation(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
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

	// Register an admin with "hf.AffiliationMgr" role
	notAffMgr, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notAffMgr",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.AffiliationMgr",
				Value: "false",
			},
		},
	})

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin2 := resp.Identity

	addAffReq := &api.AddAffiliationRequest{
		Name: "org3",
	}

	addAffResp, err := notAffMgr.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed, caller does not have 'hf.AffiliationMgr' attribute")

	addAffResp, err = admin2.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed affiliation, caller's affilation is 'org2'. Caller can't add affiliation 'org3'")

	addAffResp, err = admin.AddAffiliation(addAffReq)
	util.FatalError(t, err, "Failed to add affiliation 'org3'")
	assert.Equal(t, "org3", addAffResp.Name)

	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed affiliation 'org3' already exists")

	addAffReq.Name = "org3.dept1"
	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.NoError(t, err, "Failed to affiliation")

	registry := srv.registry
	_, err = registry.GetAffiliation("org3.dept1")
	assert.NoError(t, err, "Failed to add affiliation correctly")

	addAffReq.Name = "org4.dept1.team2"
	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed, parent affiliation does not exist. Force option is required")

	addAffReq.Force = true
	addAffResp, err = admin.AddAffiliation(addAffReq)
	assert.NoError(t, err, "Failed to add multiple affiliations with force option")

	_, err = registry.GetAffiliation("org4.dept1.team2")
	assert.NoError(t, err, "Failed to add affiliation correctly")

	_, err = registry.GetAffiliation("org4.dept1")
	assert.NoError(t, err, "Failed to add affiliation correctly")
	assert.Equal(t, "org4.dept1.team2", addAffResp.Name)
}

func TestDynamicRemoveAffiliation(t *testing.T) {
	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

	var err error

	srv := TestGetRootServer(t)
	srv.RegisterBootstrapUser("admin2", "admin2pw", "org2")
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

	_, err = admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "testuser1",
		Affiliation: "org2",
	})
	assert.NoError(t, err, "Failed to register and enroll 'testuser1'")

	notRegistrar, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notregistrar",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.AffiliationMgr",
				Value: "true",
			},
		},
	})
	assert.NoError(t, err, "Failed to register and enroll 'notregistrar'")

	registry := srv.CA.registry
	_, err = registry.GetUser("testuser1", nil)
	assert.NoError(t, err, "User should exist")

	certdbregistry := srv.CA.certDBAccessor
	certs, err := certdbregistry.GetCertificatesByID("testuser1")
	if len(certs) != 1 {
		t.Error("Failed to correctly enroll identity")
	}

	_, err = admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "testuser2",
		Affiliation: "org2",
	})
	assert.NoError(t, err, "Failed to register and enroll 'testuser1'")

	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser3",
		Affiliation: "org2.dept1",
	})

	_, err = registry.GetUser("testuser2", nil)
	assert.NoError(t, err, "User should exist")

	certs, err = certdbregistry.GetCertificatesByID("testuser2")
	if len(certs) != 1 {
		t.Error("Failed to correctly enroll identity")
	}

	removeAffReq := &api.RemoveAffiliationRequest{
		Name: "org2",
	}

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, affiliation removal not allowed")

	srv.CA.Config.Cfg.Affiliations.AllowRemove = true

	_, err = admin2.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, can't remove affiliation as the same level as caller")

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, there is an identity associated with affiliation. Need to use force option")

	removeAffReq.Force = true
	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, there is an identity associated with affiliation but identity removal is not allowed")

	srv.CA.Config.Cfg.Identities.AllowRemove = true

	_, err = notRegistrar.RemoveAffiliation(removeAffReq)
	if assert.Error(t, err, "Should have failed, there is an identity associated with affiliation but caller is not a registrar") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}

	removeResp, err := admin.RemoveAffiliation(removeAffReq)
	assert.NoError(t, err, "Failed to remove affiliation")

	_, err = registry.GetUser("testuser1", nil)
	assert.Error(t, err, "User should not exist")

	_, err = registry.GetUser("testuser2", nil)
	assert.Error(t, err, "User should not exist")

	certs, err = certdbregistry.GetCertificatesByID("testuser1")
	if certs[0].Status != "revoked" && certs[0].Reason != ocsp.AffiliationChanged {
		t.Error("Failed to correctly revoke certificate for an identity whose affiliation was removed")
	}

	certs, err = certdbregistry.GetCertificatesByID("testuser2")
	if certs[0].Status != "revoked" || certs[0].Reason != ocsp.AffiliationChanged {
		t.Error("Failed to correctly revoke certificate for an identity whose affiliation was removed")
	}

	assert.Equal(t, "org2", removeResp.Name)
	assert.Equal(t, "org2.dept1", removeResp.Affiliations[0].Name)
	assert.Equal(t, "testuser3", removeResp.Affiliations[0].Identities[0].ID)
	assert.Equal(t, "admin2", removeResp.Identities[0].ID)

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, trying to remove an affiliation that does not exist")
}

func TestDynamicModifyAffiliation(t *testing.T) {
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

	notRegistrar, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name:        "testuser1",
		Affiliation: "org2",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.AffiliationMgr",
				Value: "true",
			},
		},
	})

	_, err = admin.AddAffiliation(&api.AddAffiliationRequest{
		Name: "org2.dept1.team1",
	})
	assert.NoError(t, err, "Failed to add new affiliation")

	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Affiliation: "org2.dept1.team1",
	})
	assert.NoError(t, err, "Failed to register new user")

	modifyAffReq := &api.ModifyAffiliationRequest{
		Name:    "org2",
		NewName: "org3",
	}

	_, err = admin.ModifyAffiliation(modifyAffReq)
	assert.Error(t, err, "Should have failed, there is an identity associated with affiliation. Need to use force option")

	modifyAffReq.Force = true
	modifyResp, err := notRegistrar.ModifyAffiliation(modifyAffReq)
	if assert.Error(t, err, "Should have failed to modify affiliation, identities are affected but caller is not a registrar") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}

	modifyResp, err = admin.ModifyAffiliation(modifyAffReq)
	assert.NoError(t, err, "Failed to modify affiliation")

	registry := srv.registry
	_, err = registry.GetAffiliation("org3")
	assert.NoError(t, err, "Failed to modify affiliation to 'org3'")

	user, err := registry.GetUser("testuser1", nil)
	util.FatalError(t, err, "Failed to get user")

	userAff := cadbuser.GetAffiliation(user)
	assert.Equal(t, "org3", userAff)

	assert.Equal(t, "org3", modifyResp.Name)
	assert.Equal(t, "org3.dept1", modifyResp.Affiliations[0].Name)
	assert.Equal(t, "testuser1", modifyResp.Identities[0].ID)
}

func TestAffiliationNode(t *testing.T) {
	an := &affiliationNode{}
	an.insertByName("a.b.c")
	an.insertByName("a")
	an.insertByName("a.c.b")
	an.insertByName("a.d.b.c.e.f.g.h.i.j.z")
	root := an.GetRoot()
	assert.Equal(t, root.Name, "a")
	assert.True(t, searchChildren(root.Affiliations, "a.b"))
	assert.True(t, searchChildren(root.Affiliations, "a.b.c"))
	assert.True(t, searchChildren(root.Affiliations, "a.c"))
	assert.True(t, searchChildren(root.Affiliations, "a.d.b.c.e.f.g.h.i.j"))
	assert.False(t, searchChildren(root.Affiliations, "b"))
	assert.False(t, searchChildren(root.Affiliations, "c.b"))
	assert.False(t, searchChildren(root.Affiliations, "z"))
	an.insertByName("x")
	root = an.GetRoot()
	assert.Equal(t, root.Name, "")
}

func searchTree(resp *api.AffiliationResponse, find string) bool {
	if resp.Name == find {
		return true
	}
	return searchChildren(resp.Affiliations, find)
}

func searchChildren(children []api.AffiliationInfo, find string) bool {
	for _, child := range children {
		if child.Name == find {
			return true
		}
		if searchChildren(child.Affiliations, find) {
			return true
		}
	}
	return false
}
