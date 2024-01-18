//go:build pkcs11
// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import "github.com/hyperledger/fabric-ca/api"

// GetKeyRequest constructs and returns api.KeyRequest object based on the bccsp
// configuration options
func GetKeyRequest(cfg *CAConfig) *api.KeyRequest {
	if cfg.CSP.SW != nil {
		return &api.KeyRequest{Algo: "ecdsa", Size: cfg.CSP.SW.Security}
	} else if cfg.CSP.PKCS11 != nil {
		return &api.KeyRequest{Algo: "ecdsa", Size: cfg.CSP.PKCS11.Security}
	} else {
		return api.NewKeyRequest()
	}
}
