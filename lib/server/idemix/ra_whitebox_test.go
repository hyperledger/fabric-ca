/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"testing"

	"github.com/stretchr/testify/assert"

	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
)

func TestGetUnRevokedHandles(t *testing.T) {
	ra := &revocationAuthority{issuer: &issuer{name: "ca1", homeDir: ".", cfg: &Config{}}}
	info := &RevocationAuthorityInfo{
		Epoch:                1,
		LastHandleInPool:     100,
		NextRevocationHandle: 2,
		PrivateKey:           "",
		PublicKey:            "",
	}

	revokedCred := CredRecord{
		RevocationHandle: "10",
	}
	revokedCreds := []CredRecord{revokedCred}
	unrevokedHandles := ra.getUnRevokedHandles(info, revokedCreds)
	assert.Equal(t, 100, len(unrevokedHandles))

	revokedCred = CredRecord{
		RevocationHandle: util.B64Encode(idemix.BigToBytes(fp256bn.NewBIGint(10))),
	}
	revokedCreds = []CredRecord{revokedCred}
	unrevokedHandles = ra.getUnRevokedHandles(info, revokedCreds)
	assert.Equal(t, 99, len(unrevokedHandles))
}
