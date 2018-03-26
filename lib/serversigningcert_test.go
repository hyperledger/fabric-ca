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

func TestGetSigningCert(t *testing.T) {
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
	// Register several users
	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Type:        "client",
		Secret:      "testuserpw",
		Affiliation: "hyperledger",
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "testuser",
		Secret: "testuserpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'testuser'")

	_, err = admin.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Type:        "peer",
		Secret:      "testuser2pw",
		Affiliation: "org2",
	})
	util.FatalError(t, err, "Failed to register user 'testuser2'")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	_, err = admin.SigningCert(&api.SigningCertRequest{
		Name: "testuser",
	})
	assert.NoError(t, err, "Failed to get user signingCert")

	_, err = admin.SigningCert(&api.SigningCertRequest{
		Name: "testuser2",
	})
	assert.Error(t, err, "Should have failed without previous enrollment")

	os.RemoveAll(rootDir)
	defer os.RemoveAll(rootDir)

}
