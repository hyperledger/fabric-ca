/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"fmt"
	"testing"

	idemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestGetUnRevokedHandles(t *testing.T) {
	for _, curve := range idemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetUnRevokedHandles(t, curve)
		})
	}
}

func testGetUnRevokedHandles(t *testing.T, curveID idemix.CurveID) {
	ra := &revocationAuthority{issuer: &issuer{name: "ca1", homeDir: ".", cfg: &Config{}}, curve: idemix.CurveByID(curveID)}
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
		RevocationHandle: util.B64Encode(idemix.CurveByID(curveID).NewZrFromInt(10).Bytes()),
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
