/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scheme "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	lib "github.com/hyperledger/fabric-ca/lib"
	. "github.com/hyperledger/fabric-ca/lib/client/credential/idemix"
	cidemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/stretchr/testify/assert"
)

func TestIdemixCredential(t *testing.T) {
	for _, curveID := range []cidemix.CurveID{cidemix.Gurvy} {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curveID), func(t *testing.T) {
			testIdemixCredential(t, curveID)
		})
	}
}

func testIdemixCredential(t *testing.T, curveID cidemix.CurveID) {
	testDataDir, err := os.MkdirTemp("", strings.Replace(t.Name(), "/", "-", -1))
	assert.NoError(t, err)
	defer os.RemoveAll(testDataDir)

	testSignerConfigFile := testDataDir + "/IdemixSignerConfig"
	testIssuerPublicFile := testDataDir + "/IdemixPublicKey"

	signerConf, ipk := makeSignerConfigAndIPK(curveID, t)
	rawSignerConf, err := json.Marshal(signerConf)
	if err != nil {
		t.Fatalf("Failed to marshal signer config: %s", err.Error())
	}

	err = ioutil.WriteFile(testSignerConfigFile, rawSignerConf, 0o644)
	if err != nil {
		t.Fatalf("Failed to write signer config to file: %s", err.Error())
	}

	rawIPK, err := proto.Marshal(ipk)
	if err != nil {
		t.Fatalf("Failed to marshal IPK: %s", err.Error())
	}

	err = ioutil.WriteFile(testIssuerPublicFile, rawIPK, 0o644)
	if err != nil {
		t.Fatalf("Failed to write IPK to file: %s", err.Error())
	}

	clientHome := t.TempDir()

	signerConfig := filepath.Join(clientHome, "SignerConfig")
	client := &lib.Client{
		Config: &lib.ClientConfig{
			URL: "http://localhost:7054",
		},
		HomeDir: clientHome,
	}
	err = client.Init()
	if err != nil {
		t.Fatalf("Failed to initialize client: %s", err.Error())
	}

	idemixCred := NewCredential(signerConfig, client, curveID)

	assert.Equal(t, idemixCred.Type(), CredType, "Type for a IdemixCredential instance must be Idemix")
	_, err = idemixCred.Val()
	assert.Error(t, err, "Val should return error if credential has not been loaded from disk or set")
	if err != nil {
		assert.Equal(t, err.Error(), "Idemix credential value is not set")
	}
	_, err = idemixCred.EnrollmentID()
	assert.Error(t, err, "EnrollmentID should return an error if credential has not been loaded from disk or set")
	if err != nil {
		assert.Equal(t, err.Error(), "Idemix credential value is not set")
	}
	body := []byte("hello")
	req, err := http.NewRequest("GET", "localhost:7054/enroll", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %s", err.Error())
	}
	_, err = idemixCred.CreateToken(req, body)
	assert.Error(t, err, "CreateToken should return an error if credential has not been loaded from disk or set")
	if err != nil {
		assert.Equal(t, err.Error(), "Idemix credential value is not set")
	}

	err = idemixCred.SetVal("hello")
	assert.Error(t, err, "SetVal should fail as it expects an object of type *SignerConfig")

	err = idemixCred.Store()
	assert.Error(t, err, "Store should return an error if credential has not been set")

	err = idemixCred.Load()
	assert.Errorf(t, err, "Load should fail as %s is not found", signerConfig)

	err = ioutil.WriteFile(signerConfig, []byte("hello"), 0o744)
	if err != nil {
		t.Fatalf("Failed to write to file %s: %s", signerConfig, err.Error())
	}
	err = idemixCred.Load()
	assert.Errorf(t, err, "Load should fail as %s contains invalid data", signerConfig)

	err = lib.CopyFile(testSignerConfigFile, signerConfig)
	if err != nil {
		t.Fatalf("Failed to copy %s to %s: %s", testSignerConfigFile, signerConfig, err.Error())
	}

	clientPubKeyFile := filepath.Join(clientHome, "msp/IssuerPublicKey")
	err = os.MkdirAll(filepath.Join(clientHome, "msp"), 0o744)
	if err != nil {
		t.Fatalf("Failed to create msp directory: %s", err.Error())
	}
	err = lib.CopyFile(testIssuerPublicFile, clientPubKeyFile)
	if err != nil {
		t.Fatalf("Failed to copy %s to %s: %s", testIssuerPublicFile, clientPubKeyFile, err.Error())
	}

	err = idemixCred.Load()
	assert.NoError(t, err, "Load should not return error as %s exists and is valid", signerConfig)

	val, err := idemixCred.Val()
	assert.NoError(t, err, "Val should not return error as credential is loaded")

	signercfg, _ := val.(*SignerConfig)
	cred := signercfg.GetCred()
	assert.NotNil(t, cred)
	assert.True(t, len(cred) > 0, "Credential bytes length should be more than zero")

	enrollID := signercfg.GetEnrollmentID()
	assert.Equal(t, "admin", enrollID, "Enrollment ID of the Idemix credential in testdata/IdemixSignerConfig should be admin")

	sk := signercfg.GetSk()
	assert.NotNil(t, sk, "secret key should not be nil")
	assert.True(t, len(sk) > 0, "Secret key bytes length should be more than zero")

	signercfg.GetOrganizationalUnitIdentifier()
	role := signercfg.GetRole()
	assert.False(t, idemix.CheckRole(role, idemix.ADMIN))

	err = idemixCred.SetVal(val)
	assert.NoError(t, err, "Setting the value that we got from the credential should not return an error")

	if err = os.Chmod(signerConfig, 0o000); err != nil {
		t.Fatalf("Failed to chmod SignerConfig file %s: %v", signerConfig, err)
	}
	err = idemixCred.Store()
	assert.Errorf(t, err, "Store should fail as %s is not writable", signerConfig)

	if err = os.Chmod(signerConfig, 0o644); err != nil {
		t.Fatalf("Failed to chmod SignerConfig file %s: %v", signerConfig, err)
	}
	err = idemixCred.Store()
	assert.NoError(t, err, "Store should not fail as %s is writable and Idemix credential value is set", signerConfig)

	_, err = idemixCred.Val()
	assert.NoError(t, err, "Val should not return error as Idemix credential has been loaded")

	_, err = idemixCred.EnrollmentID()
	assert.NoError(t, err, "EnrollmentID should not return error as Idemix credential has been loaded")

	if err = os.Chmod(clientPubKeyFile, 0o000); err != nil {
		t.Fatalf("Failed to chmod SignerConfig file %s: %v", clientPubKeyFile, err)
	}
	_, err = idemixCred.CreateToken(req, body)
	assert.Errorf(t, err, "CreateToken should fail as %s is not readable", clientPubKeyFile)

	if err = os.Chmod(clientPubKeyFile, 0o644); err != nil {
		t.Fatalf("Failed to chmod SignerConfig file %s: %v", clientPubKeyFile, err)
	}

	origCred := signercfg.Cred
	signercfg.Cred = []byte("fakecred")
	_, err = idemixCred.CreateToken(req, body)
	assert.Error(t, err, "CreateToken should fail credential is junk bytes in the signerconfig")
	signercfg.Cred = origCred

	origCri := signercfg.CredentialRevocationInformation
	signercfg.CredentialRevocationInformation = []byte("fakecred")
	_, err = idemixCred.CreateToken(req, body)
	assert.Error(t, err, "CreateToken should fail credential revocation information is junk bytes in the signerconfig")
	signercfg.CredentialRevocationInformation = origCri

	_, err = idemixCred.CreateToken(req, body)
	assert.NoError(t, err, "CreateToken should not return error as Idemix credential has been loaded")

	_, err = idemixCred.RevokeSelf()
	assert.Error(t, err, "RevokeSelf should fail as it is not implemented for Idemix credential")
}

func makeSignerConfigAndIPK(curveID cidemix.CurveID, t *testing.T) (SignerConfig, *scheme.IssuerPublicKey) {
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

	sk := curve.NewZrFromBytes(ik.Isk)

	revKey, err := idemix.GenerateLongTermRevocationKey()
	assert.NoError(t, err)

	cri, err := idemix.CreateCRI(revKey, nil, 1, scheme.ALG_NO_REVOCATION, rand, idemix.Translator)
	assert.NoError(t, err)

	criBytes, err := proto.Marshal(cri)
	assert.NoError(t, err)

	nonce := curve.NewRandomZr(rand)

	credReq, err := idemix.NewCredRequest(sk, nonce.Bytes(), ik.Ipk, rand, idemix.Translator)
	assert.NoError(t, err)

	cred, err := idemix.NewCredential(ik, credReq, numericalAttrs, rand, idemix.Translator)
	assert.NoError(t, err)

	credBytes, err := proto.Marshal(cred)
	assert.NoError(t, err)

	signerSK := curve.NewRandomZr(rand)

	return SignerConfig{
		CredentialRevocationInformation: criBytes,
		Cred:                            credBytes,
		EnrollmentID:                    "admin",
		OrganizationalUnitIdentifier:    "MSPID",
		Sk:                              signerSK.Bytes(),
	}, ik.Ipk
}
