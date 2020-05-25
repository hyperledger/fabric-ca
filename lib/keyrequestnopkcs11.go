// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import "github.com/hyperledger/fabric-ca/internal/pkg/api"

// GetKeyRequest constructs and returns api.KeyRequest object based on the bccsp
// configuration options
func GetKeyRequest(cfg *CAConfig) *api.KeyRequest {
	if cfg.CSP.SwOpts != nil {
		return &api.KeyRequest{Algo: "ecdsa", Size: cfg.CSP.SwOpts.SecLevel}
	}
	return api.NewKeyRequest()
}
