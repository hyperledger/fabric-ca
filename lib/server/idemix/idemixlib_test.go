/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	cidemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestIdemixPanic(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testIdemixPanic(t, curve)
		})
	}
}

func generatePublicPrivateKeyPair(t *testing.T, curveID cidemix.CurveID) (string, string, string, error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), strings.Replace(t.Name(), "/", "-", -1))
	assert.NoError(t, err)

	testPublicKeyFile := filepath.Join(tmpDir, "IdemixPublicKey")
	testSecretKeyFile := filepath.Join(tmpDir, "IdemixSecretKey")

	pk, sk := makePubPrivKeyPair(curveID, t)
	err = ioutil.WriteFile(testPublicKeyFile, pk, 0o644)
	if err != nil {
		t.Fatalf("Failed writing public key to file: %s", err.Error())
	}

	err = ioutil.WriteFile(testSecretKeyFile, sk, 0o644)
	if err != nil {
		t.Fatalf("Failed writing private key to file: %s", err.Error())
	}
	return testPublicKeyFile, testSecretKeyFile, tmpDir, err
}

func makePubPrivKeyPair(curveID cidemix.CurveID, t *testing.T) ([]byte, []byte) {
	curve := cidemix.CurveByID(curveID)
	rand, err := curve.Rand()
	assert.NoError(t, err)

	attrs := []string{idemix.AttrOU, idemix.AttrRole, idemix.AttrEnrollmentID, idemix.AttrRevocationHandle}
	var numericalAttrs []*math.Zr
	for _, attr := range attrs {
		numericalAttrs = append(numericalAttrs, curve.HashToZr([]byte(attr)))
	}

	idemix := cidemix.InstanceForCurve(curveID)
	ik, err := idemix.NewIssuerKey(attrs, rand, idemix.Translator)
	assert.NoError(t, err)

	ipk, err := proto.Marshal(ik.Ipk)
	assert.NoError(t, err)

	return ipk, ik.Isk
}

func testIdemixPanic(t *testing.T, curveID cidemix.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := generatePublicPrivateKeyPair(t, curveID)
	defer os.RemoveAll(tmpDir)

	curve := cidemix.CurveByID(curveID)
	nonce := curve.NewZrFromInt(1)
	credReq, _, err := newIdemixCredentialRequest(t, nonce, curveID, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create credential request: %s", err.Error())
	}

	libImpl := idemix.NewLib(curveID)
	_, err = libImpl.NewCredential(nil, credReq, nil)
	util.ErrorContains(t, err, "failure: runtime error", "NewCredential should have caught panic, and returned an error")
}
