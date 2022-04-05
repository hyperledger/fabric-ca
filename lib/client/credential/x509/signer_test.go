/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package x509_test

import (
	"path/filepath"
	"testing"

	. "github.com/hyperledger/fabric-ca/lib/client/credential/x509"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestNewSignerError(t *testing.T) {
	_, err := NewSigner(nil, []byte{})
	assert.Error(t, err, "NewSigner should return an error if cert byte array is empty")
}

func TestNewSigner(t *testing.T) {
	certBytes, err := util.ReadFile(filepath.Join(testDataDir, "ec256-1-cert.pem"))
	if err != nil {
		t.Fatalf("Failed to read the cert: %s", err.Error())
	}
	signer, err := NewSigner(nil, certBytes)
	assert.NoError(t, err, "NewSigner should not return an error if cert bytes are valid")

	assert.NotNil(t, signer.GetX509Cert())
	assert.Nil(t, signer.Key())
	assert.NotEmpty(t, signer.GetName())
	_, err = signer.Attributes()
	assert.NoError(t, err)
}
