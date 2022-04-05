/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	dbuser "github.com/hyperledger/fabric-ca/lib/server/user"
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
	if userInfo.(*dbuser.Impl).State != 1 {
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
	if userInfo.(*dbuser.Impl).State != 1 {
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

func TestPasswordLimit(t *testing.T) {
	cleanTestSlateSE(t)
	defer cleanTestSlateSE(t)

	passLimit := 3

	srv := TestGetRootServer(t)
	srv.CA.Config.Cfg.Identities.PasswordAttempts = passLimit
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	client := getTestClient(rootPort)
	enrollResp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll 'admin' user")
	admin := enrollResp.Identity

	_, err = admin.Register(&api.RegistrationRequest{
		Name:   "user1",
		Secret: "user1pw",
	})
	util.FatalError(t, err, "Failed to register 'user1' user")

	// Reach maximum incorrect password limit
	for i := 0; i < passLimit; i++ {
		_, err = client.Enroll(&api.EnrollmentRequest{
			Name:   "user1",
			Secret: "badpass",
		})
		assert.Error(t, err, "Enroll for user 'user1' should fail due to bad password")
	}
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "badpass",
	})
	util.ErrorContains(t, err, "73", "Should fail, incorrect password limit reached")

	// Admin modifying identity, confirm that just modifying identity does not reset attempt
	// count. Incorrect password attempt count should only be reset to zero, if password
	// is modified.
	modReq := &api.ModifyIdentityRequest{
		ID: "user1",
	}

	modReq.Type = "client"
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "user1pw",
	})
	assert.Error(t, err, "Should failed to enroll")

	// Admin reset password
	modReq.Secret = "newPass"
	_, err = admin.ModifyIdentity(modReq)
	assert.NoError(t, err, "Failed to modify identity")

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "newPass",
	})
	assert.NoError(t, err, "Failed to enroll using new password after admin reset password")

	// Test that if password is entered correctly before reaching incorrect password limit,
	// the incorrect password count is reset back to 0
	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "badPass",
	})
	assert.Error(t, err, "Enroll for user 'user1' should fail due to bad password")

	registry := srv.CA.DBAccessor()
	user1, err := registry.GetUser("user1", nil)
	util.FatalError(t, err, "Failed to get 'user1' from database")
	assert.Equal(t, 1, user1.GetFailedLoginAttempts())

	_, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "user1",
		Secret: "newPass",
	})
	assert.NoError(t, err, "Failed to enroll user with correct password")

	user1, err = registry.GetUser("user1", nil)
	util.FatalError(t, err, "Failed to get 'user1' from database")
	assert.Equal(t, 0, user1.GetFailedLoginAttempts())
}

func TestCertificateExpiration(t *testing.T) {
	cleanTestSlateSE(t)
	defer cleanTestSlateSE(t)

	srv := TestGetRootServer(t)
	err := srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	caCertPem, _ := srv.CA.getCACert()
	caCert, _ := util.GetX509CertificateFromPEM(caCertPem)

	client := getTestClient(rootPort)

	csrPEM, _, err := client.GenCSR(&api.CSRInfo{CN: "admin"}, "admin")
	assert.NoError(t, err, "Failed to generate CSR")

	reqNet := &api.EnrollmentRequestNet{
		SignRequest: signer.SignRequest{
			Request: string(csrPEM),
			// requesting certificate with validity time wider then CA cert
			NotBefore: caCert.NotBefore.Add(-1 * time.Hour),
			NotAfter:  caCert.NotAfter.Add(24 * time.Hour),
		},
	}

	body, err := util.Marshal(reqNet, "SignRequest")
	assert.NoError(t, err, "Failed to marshal enroll request")

	// Send the CSR to the fabric-ca server with basic auth header
	post, err := client.newPost("enroll", body)
	assert.NoError(t, err, "Failed to create post request")
	post.SetBasicAuth("admin", "adminpw")

	var result api.EnrollmentResponseNet
	err = client.SendReq(post, &result)
	assert.NoError(t, err, "Failed to enroll")

	// verify response
	certBytes, err := util.B64Decode(result.Cert)
	assert.NoError(t, err, "Failed to convert certificate")
	userCert, err := util.GetX509CertificateFromPEM(certBytes)
	assert.NoError(t, err, "Failed to extract certificate from enroll response")

	// certificate validity is in range of CA cert validity
	assertValidityInRange(t, userCert.NotBefore, userCert.NotAfter, caCert.NotBefore, caCert.NotAfter)

	// ensure that CA issue a certificate with starting time as early as possible
	assert.True(t, userCert.NotBefore.Equal(caCert.NotBefore), "certificate starting time should be as early as possible")
}

func assertValidityInRange(t assert.TestingT, certNotBefore time.Time, certNotAfter time.Time, caNotBefore time.Time, caNotAfter time.Time) {
	// caCertNotBefore <= certNotBefore < certNotAfter <= caCertNotAfter

	assert.True(t, certNotBefore.Before(certNotAfter), "certificate without valid time NotBefore is not before NotAfter")

	assert.False(t, certNotBefore.Before(caNotBefore),
		"certificate NotBefore %v is before CA cert NotBefore %v", certNotBefore, caNotBefore)
	assert.False(t, certNotAfter.After(caNotAfter),
		"user certificate NotAfter %v is after CA cert NotAfter %v", certNotAfter, caNotAfter)
}
