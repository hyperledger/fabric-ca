/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"math/big"
	"testing"

	"github.com/IBM/mathlib/driver/common"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetUnRevokedHandles(t *testing.T) {
	ra := &revocationAuthority{issuer: &IssuerInst{Name: "ca1", HomeDir: ".", Cfg: &Config{}}}
	info := &RevocationAuthorityInfo{
		Epoch:                1,
		LastHandleInPool:     100,
		NextRevocationHandle: 2,
	}

	revokedCred := CredRecord{
		RevocationHandle: "10",
	}
	revokedCreds := []CredRecord{revokedCred}
	unrevokedHandles := ra.getUnRevokedHandles(info, revokedCreds)
	assert.Equal(t, 100, len(unrevokedHandles))

	revokedCred = CredRecord{
		RevocationHandle: util.B64Encode(common.BigToBytes(big.NewInt(int64(10)))),
	}
	revokedCreds = []CredRecord{revokedCred}
	unrevokedHandles = ra.getUnRevokedHandles(info, revokedCreds)
	assert.Equal(t, 99, len(unrevokedHandles))
}

func TestDoTransactionNilDB(t *testing.T) {
	f := func(tx db.FabricCATx, args ...interface{}) (interface{}, error) {
		return nil, nil
	}
	_, err := doTransaction("", nil, f)
	assert.Error(t, err)
}
