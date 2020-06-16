// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"testing"

	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/pkcs11"
	"github.com/stretchr/testify/assert"
)

func TestConfigureBCCSP(t *testing.T) {
	mspDir := "msp"
	lib, pin, label := pkcs11.FindPKCS11Lib()
	opts := &factory.FactoryOpts{
		ProviderName: "PKCS11",
		Pkcs11Opts: &pkcs11.PKCS11Opts{
			SecLevel:   256,
			HashFamily: "SHA2",
			Library:    lib,
			Label:      label,
			Pin:        pin,
		},
	}

	err := ConfigureBCCSP(&opts, mspDir, "")
	if err != nil {
		t.Fatalf("Failed initialization 1 of BCCSP: %s", err)
	}
}

func TestSanitizePKCS11Opts(t *testing.T) {
	lib, pin, label := pkcs11.FindPKCS11Lib()
	opts := pkcs11.PKCS11Opts{
		SecLevel:   256,
		HashFamily: "SHA2",
		Library:    lib,
		Label:      label,
		Pin:        pin,
	}
	p11opts := sanitizePKCS11Opts(opts)
	assert.Equal(t, p11opts.Label, "******")
	assert.Equal(t, p11opts.Pin, "******")
}
