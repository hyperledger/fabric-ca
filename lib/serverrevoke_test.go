/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestParseInput(t *testing.T) {
	input := "01:AA:22:bb"

	parsedInput := parseInput(input)

	assert.NotContains(t, parsedInput, ":", "failed to correctly remove colons from input")
	assert.NotEqual(t, string(parsedInput[0]), "0", "failed to correctly remove leading zeros from input")
	assert.NotContains(t, parsedInput, "AA", "failed to correctly lowercase capital letters")
}

func TestIdemixCredRevokedUser(t *testing.T) {
	srv := TestGetRootServer(t)
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(rootClientDir)

	c := TestGetRootClient()
	req := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	}

	enrollResp, err := c.Enroll(req)
	util.FatalError(t, err, "Failed to enroll 'admin'")
	admin := enrollResp.Identity

	_, err = admin.Register(&api.RegistrationRequest{
		Name:   "user1",
		Secret: "user1pw",
	})
	util.FatalError(t, err, "Failed to register 'user1' by 'admin' user")

	// Enroll a user to get back Idemix credential
	req.Name = "user1"
	req.Secret = "user1pw"
	req.Type = "idemix"

	enrollIdmixResp, err := c.Enroll(req)
	util.FatalError(t, err, "Failed to enroll 'user1'")
	idemixUser := enrollIdmixResp.Identity

	// Revoke the user that only posses an Idemix credential
	_, err = admin.Revoke(&api.RevocationRequest{
		Name: "user1",
	})
	util.FatalError(t, err, "Failed to revoke 'user1' by 'admin' user")

	// Revoked user should not be able to make requests to the Fabric CA server
	_, err = idemixUser.Register(&api.RegistrationRequest{
		Name:   "user2",
		Secret: "user2pw",
	})
	t.Log("Error: ", err)
	util.ErrorContains(t, err, "71", "Revoked user with only Idemix credential, should not be able to make requests to the server")
}

// Test to make sure the UpdateNextandLastHandle SQL statement executes currently agains a database
func TestUpdatingRevocationHandleQuery(t *testing.T) {
	srv := TestGetRootServer(t)
	srv.CA.Config.Idemix.RHPoolSize = 5
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()
	defer os.RemoveAll(rootDir)

	c := TestGetRootClient()
	req := &api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
		Type:   "idemix",
	}

	// Exhaust the RHPoolSize, trigging updating the database with a new revocation handle
	for i := 1; i <= 6; i++ {
		_, err := c.Enroll(req)
		assert.NoError(t, err, "Failed to enroll 'admin'")
	}
}

func TestRevokeSelf(t *testing.T) {
	var err error
	srv := TestGetRootServer(t)
	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()
	defer os.RemoveAll("rootDir")
	defer os.RemoveAll("../testdata/msp")

	client := getTestClient(7075)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity
	name := "testuser"
	password := "password"
	_, err = admin.Register(&api.RegistrationRequest{
		Name:   name,
		Secret: password,
	})
	util.FatalError(t, err, "Failed to register user 'testuser'")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   name,
		Secret: password,
	})
	util.FatalError(t, err, "Failed to enroll user 'testuser'")
	testuser := resp.Identity

	db := srv.CA.CertDBAccessor()
	cert, err := db.GetCertificatesByID("testuser")
	util.FatalError(t, err, "Failed to get certificvate for 'testuser'")

	_, err = testuser.Revoke(&api.RevocationRequest{
		Serial: cert[0].Serial,
		AKI:    cert[0].AKI,
	})
	assert.NoError(t, err, "Failed to revoke one's own certificate using serial and AKI")

	resp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   name,
		Secret: password,
	})
	util.FatalError(t, err, "Failed to enroll user 'testuser'")
	testuser = resp.Identity

	_, err = testuser.RevokeSelf()
	assert.NoError(t, err, "Failed to revoke one self")
}
