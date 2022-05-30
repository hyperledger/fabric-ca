/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	idemix2 "github.com/hyperledger/fabric-ca/lib/common/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/stretchr/testify/assert"
)

// TestIssuer tests issuer
func TestIssuer(t *testing.T) {
	for _, curve := range idemix2.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testIssuer(t, curve)
		})
	}
}

// TestIssuer tests issuer
func testIssuer(t *testing.T, curveID idemix2.CurveID) {
	testdir := t.TempDir()
	err := os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	issuer := issuer{name: "ca1", homeDir: testdir, cfg: &Config{}, db: &db.DB{}, idemixLib: NewLib(curveID)}
	assert.NotNil(t, issuer.DB(), "DB() should not return nil")
	assert.NotNil(t, issuer.IdemixLib(), "GetIdemixLib() should not return nil")
	assert.Equal(t, "ca1", issuer.Name())
	assert.Nil(t, issuer.IssuerCredential(), "IssueCredential() should return nil")
	assert.Nil(t, issuer.RevocationAuthority(), "RevocationAuthority() should return nil")
	assert.Nil(t, issuer.NonceManager(), "NonceManager() should return nil")
	assert.Nil(t, issuer.CredDBAccessor(), "CredDBAccessor() should return nil")

	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should return not return an error if db is nil")

	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "IssuerPublicKey should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	_, err = issuer.RevocationPublicKey()
	assert.Error(t, err, "RevocationPublicKey should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	_, err = issuer.IssueCredential(nil)
	assert.Error(t, err, "IssueCredential should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	_, err = issuer.GetCRI(nil)
	assert.Error(t, err, "GetCRI should return an error because issuer is not initialized")
	assert.Equal(t, "Issuer is not initialized", err.Error())

	issuer.isInitialized = true
	err = issuer.Init(false, nil, &dbutil.Levels{Credential: 1, RAInfo: 1, Nonce: 1})
	assert.NoError(t, err, "Init should return not return an error if it is already initialized")
}

func TestIssuerPublicKey(t *testing.T) {
	for _, curve := range idemix2.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testIssuerPublicKey(t, curve)
		})
	}
}

func testIssuerPublicKey(t *testing.T, curveID idemix2.CurveID) {
	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	testdir := t.TempDir()

	defer os.RemoveAll(testdir)
	err = os.MkdirAll(filepath.Join(testdir, "msp/keystore"), 0o777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	issuer := issuer{
		name:          "ca1",
		homeDir:       testdir,
		cfg:           &Config{IssuerPublicKeyfile: "IssuerPublicKey", IssuerSecretKeyfile: "IssuerSecretKey"},
		db:            &db.DB{},
		idemixLib:     NewLib(curveID),
		isInitialized: true,
	}
	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, NewLib(curveID), curveID)
	issuer.issuerCred = issuerCred
	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "issuer.IssuerCredential() should return an error as issuer credential has not been loaded")

	err = issuer.issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential: %s", err.Error())
	}
	ik, _ := issuerCred.GetIssuerKey()
	ik.Ipk = nil
	_, err = issuer.IssuerPublicKey()
	assert.Error(t, err, "issuer.IssuerCredential() should return an error as it should fail to marshal issuer public key")
}

func GeneratePublicPrivateKeyPair(t *testing.T, curveID idemix2.CurveID) (string, string, string, error) {
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

func TestWallClock(t *testing.T) {
	clock := wallClock{}
	assert.NotNil(t, clock.Now())
}

func makePubPrivKeyPair(curveID idemix2.CurveID, t *testing.T) ([]byte, []byte) {
	curve := idemix2.CurveByID(curveID)
	rand, err := curve.Rand()
	assert.NoError(t, err)

	attrs := []string{AttrOU, AttrRole, AttrEnrollmentID, AttrRevocationHandle}
	var numericalAttrs []*math.Zr
	for _, attr := range attrs {
		numericalAttrs = append(numericalAttrs, curve.HashToZr([]byte(attr)))
	}

	idemix := idemix2.InstanceForCurve(curveID)
	ik, err := idemix.NewIssuerKey(attrs, rand, idemix.Translator)
	assert.NoError(t, err)

	ipk, err := proto.Marshal(ik.Ipk)
	assert.NoError(t, err)

	return ipk, ik.Isk
}
