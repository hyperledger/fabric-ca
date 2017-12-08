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
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestDynamicIdentityConfig(t *testing.T) {
	testDir := "dynIdentity"
	os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)

	server := TestGetServer(7090, testDir, "", 1, t)
	if server == nil {
		t.Fatalf("Failed to get server")
	}

	err := server.Start()
	util.FatalError(t, err, "Failed to start server")

	client := getTestClient(7090)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll 'admin' user")

	id := resp.Identity
	_, err = id.GetAllIdentities("")
	assert.Error(t, err, "Should have failed, functionality not yet implemented")

	_, err = id.GetIdentity("testuser", "")
	assert.Error(t, err, "Should have failed, functionality not yet implemented")

	addReq := &api.AddIdentityRequest{}
	addReq.ID = "testuser"
	_, err = id.AddIdentity(addReq)
	assert.Error(t, err, "Should have failed, functionality not yet implemented")

	modifyReq := &api.ModifyIdentityRequest{}
	modifyReq.ID = "testuser"
	_, err = id.ModifyIdentity(modifyReq)
	assert.Error(t, err, "Should have failed, functionality not yet implemented")

	_, err = id.RemoveIdentity(&api.RemoveIdentityRequest{
		ID: "testuser",
	})
	assert.Error(t, err, "Should have failed, functionality not yet implemented")

}
