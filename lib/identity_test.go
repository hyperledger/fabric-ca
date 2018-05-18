/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	clientcred "github.com/hyperledger/fabric-ca/lib/client/credential"
	"github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/stretchr/testify/assert"
)

func getIdentity(t *testing.T) *Identity {
	cred := x509.NewCredential("../testdata/ec.pem", "../testdata/ec-key.pem", nil)
	err := cred.Load()
	if err != nil {
		t.Fatalf("Failed to load credential from non existant file ../tesdata/ec.pem: %s", err.Error())
	}
	id := NewIdentity(nil, "test", []clientcred.Credential{cred})
	return id
}

func TestIdentity(t *testing.T) {
	id := getIdentity(t)
	testGetName(id, t)
	testGetECert(id, t)
}

func TestBadStoreIdentity(t *testing.T) {
	id := &Identity{}
	err := id.Store()
	if err == nil {
		t.Error("TestBadStoreIdentity passed but should have failed")
	}
}

func TestBadRegistration(t *testing.T) {
	id := &Identity{}
	req := &api.RegistrationRequest{}
	_, err := id.Register(req)
	if err == nil {
		t.Error("Empty registration request should have failed")
	}
}

func testGetName(id *Identity, t *testing.T) {
	name := id.GetName()
	if name != "test" {
		t.Error("Incorrect name retrieved")
	}
}

func testGetECert(id *Identity, t *testing.T) {
	ecert := id.GetECert()
	if ecert == nil {
		t.Error("No ECert was returned")
	}
}

func TestGetCertificatesErr(t *testing.T) {
	id := getIdentity(t)
	id.client = &Client{
		Config: &ClientConfig{},
	}
	err := id.GetCertificates(&api.GetCertificatesRequest{}, nil)
	assert.Error(t, err, "Should fail, no server to contact")
}
