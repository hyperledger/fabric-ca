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

func TestStateUpdate(t *testing.T) {
	cleanTestSlateSE(t)
	defer cleanTestSlateSE(t)

	var err error
	srv := TestGetRootServer(t)

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	client := getTestClient(rootPort)
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	registry := srv.CA.DBAccessor()
	userInfo, err := registry.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to get user 'admin' from database")
	// User state should have gotten updated to 1 after a successful enrollment
	if userInfo.(*DBUser).State != 1 {
		t.Error("Incorrect state set for user")
	}

	// Send bad CSR to cause the enroll to fail but the login to succeed
	reqNet := &api.EnrollmentRequestNet{}
	reqNet.SignRequest.Request = "badcsr"
	body, err := util.Marshal(reqNet, "SignRequest")
	assert.NoError(t, err, "Failed to marshal enroll request")

	// Send the CSR to the fabric-ca server with basic auth header
	post, err := client.newPost("enroll", body)
	assert.NoError(t, err, "Failed to create post request")
	post.SetBasicAuth("admin", "adminpw")
	err = client.SendReq(post, nil)
	if assert.Error(t, err, "Should have failed due to bad csr") {
		assert.Contains(t, err.Error(), "CSR Decode failed")
	}

	// State should not have gotten updated because the enrollment failed
	userInfo, err = registry.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to get user 'admin' from database")
	if userInfo.(*DBUser).State != 1 {
		t.Error("Incorrect state set for user")
	}

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

}

func cleanTestSlateSE(t *testing.T) {
	err := os.RemoveAll(rootDir)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	err = os.RemoveAll("../testdata/msp")
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
}
