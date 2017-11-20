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
	"os"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetAllAffiliations(t *testing.T) {
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

	result, err := captureOutput(admin.GetAllAffiliations, "", AffiliationDecoder)
	assert.NoError(t, err, "Failed to get all affiliations")

	affiliations := []AffiliationRecord{}
	err = srv.CA.db.Select(&affiliations, srv.CA.db.Rebind("SELECT * FROM affiliations"))
	if err != nil {
		t.Error("Failed to get all affiliations in database")
	}

	for _, aff := range affiliations {
		if !strings.Contains(result, aff.Name) {
			t.Error("Failed to get all appropriate affiliations")
		}
	}

	// admin2's affilations is "org2"
	result, err = captureOutput(admin2.GetAllAffiliations, "", AffiliationDecoder)
	assert.NoError(t, err, "Failed to get all affiliations for admin2")

	if !strings.Contains(result, "org2") {
		t.Error("Incorrect affiliation received")
	}

	notAffMgr, err := admin.RegisterAndEnroll(&api.RegistrationRequest{
		Name: "notAffMgr",
	})
	util.FatalError(t, err, "Failed to register a user that is not affiliation manager")

	err = notAffMgr.GetAllAffiliations("", AffiliationDecoder)
	if assert.Error(t, err, "Should have failed, as the caller does not have the attribute 'hf.AffiliationMgr'") {
		assert.Contains(t, err.Error(), "User does not have attribute 'hf.AffiliationMgr'")
	}

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

	getAffResp, err := admin.GetAffiliation("org2.dept1", "")
	assert.NoError(t, err, "Failed to get requested affiliations")

	if getAffResp.Info.Name != "org2.dept1" {
		t.Error("Failed to get correct affiliation")
	}

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

	addAffReq := &api.AddAffiliationRequest{}
	addAffReq.Info.Name = "org3"

	_, err = admin.AddAffiliation(addAffReq)
	assert.Error(t, err, "Should have failed, not yet implemented")
}

func TestDynamicRemoveAffiliation(t *testing.T) {
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

	removeAffReq := &api.RemoveAffiliationRequest{
		Name: "org3",
	}

	_, err = admin.RemoveAffiliation(removeAffReq)
	assert.Error(t, err, "Should have failed, not yet implemented")
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

	modifyAffReq := &api.ModifyAffiliationRequest{
		Name: "org3",
	}
	modifyAffReq.Info.Name = "org2"
	_, err = admin.ModifyAffiliation(modifyAffReq)
	assert.Error(t, err, "Should have failed, not yet implemented")
}
