/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	math "github.com/IBM/mathlib"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/api"
	cidemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestIdemixEnrollInvalidBasicAuth(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("", errors.New("bad credentials"))
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx}
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should fail if basic auth credentials are invalid")
}

func TestIdemixEnrollInvalidTokenAuth(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", errors.New("bad credentials"))
	ctx.On("IsBasicAuth").Return(false)
	handler := EnrollRequestHandler{Ctx: ctx}
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should fail if token auth credentials are invalid")
}

func TestIdemixEnrollBadReqBody(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx}
	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(errors.New("Invalid request body"))
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error if reading body fails")
}

func TestHandleIdemixEnrollForNonce(t *testing.T) {
	for _, curveID := range cidemix.Curves {
		testHandleIdemixEnrollForNonce(t, curveID)
	}
}

func testHandleIdemixEnrollForNonce(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	idemixlib := new(mocks.Lib)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}

	rmo := curve.NewRandomZr(rand)
	rmo.Mod(curve.GroupOrder)
	idemixlib.On("GetRand").Return(rand, nil)
	idemixlib.On("RandModOrder", rand).Return(rmo)
	ctx.On("IsBasicAuth").Return(true)
	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("IdemixRand").Return(rand)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(curve.NewRandomZr(rand), nil)
	issuer.On("NonceManager").Return(nm)
	handler := EnrollRequestHandler{Ctx: ctx, Issuer: issuer, IdmxLib: idemixlib}
	_, err = handler.HandleRequest()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForNonceTokenAuth(t *testing.T) {
	for _, curveID := range cidemix.Curves {
		testHandleIdemixEnrollForNonceTokenAuth(t, curveID)
	}
}

func testHandleIdemixEnrollForNonceTokenAuth(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)

	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)

	idemixlib := new(mocks.Lib)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}

	rmo := curve.NewRandomZr(rand)
	rmo.Mod(curve.GroupOrder)

	idemixlib.On("GetRand").Return(rand, nil)
	idemixlib.On("RandModOrder", rand).Return(rmo)

	ctx.On("IsBasicAuth").Return(false)

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("IdemixRand").Return(rand)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(curve.NewRandomZr(rand), nil)
	issuer.On("NonceManager").Return(nm)

	ctx.On("GetIssuer").Return(issuer, nil)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	_, err = handler.HandleRequest()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForNonceError(t *testing.T) {
	for _, curveID := range cidemix.Curves {
		testHandleIdemixEnrollForNonceError(t, curveID)
	}
}

func testHandleIdemixEnrollForNonceError(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)

	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)

	idemixlib := new(mocks.Lib)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}

	rmo := curve.NewRandomZr(rand)
	rmo.Mod(curve.GroupOrder)

	idemixlib.On("GetRand").Return(rand, nil)
	idemixlib.On("RandModOrder", rand).Return(rmo)

	ctx.On("IsBasicAuth").Return(false)

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("IdemixRand").Return(rand)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(nil, errors.New("Failed to generate nonce"))
	issuer.On("NonceManager").Return(nm)

	ctx.On("GetIssuer").Return(issuer, nil)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return an error because NonceManager.GetNonce returned an error")
}

func TestHandleIdemixEnrollForCredentialError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testHandleIdemixEnrollForCredentialError(t, curve)
		})
	}
}

func testHandleIdemixEnrollForCredentialError(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)

	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)

	idemixlib := new(mocks.Lib)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}

	rmo := curve.NewRandomZr(rand)
	rmo.Mod(curve.GroupOrder)

	idemixlib.On("GetRand").Return(rand, nil)
	idemixlib.On("RandModOrder", rand).Return(rmo, nil)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixlib, curveID)
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rand)

	ctx.On("GetIssuer").Return(issuer, nil)
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer, CurveID: curveID, Curve: curve, Translator: cidemix.InstanceForCurve(curveID).Translator}
	nonce, err := handler.GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %s", err.Error())
	}

	credReq, _, err := newIdemixCredentialRequest(t, nonce, curveID, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create credential request: %s", err.Error())
	}
	f := getReadBodyFunc(t, credReq)
	req := api.IdemixEnrollmentRequestNet{}
	ctx.On("ReadBody", &req).Return(f)

	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error if IssuerCredential has not been loaded from disk")
	if err != nil {
		assert.Contains(t, err.Error(), "Failed to get Idemix issuer key for the CA")
	}

	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ctx.On("GetCaller").Return(nil, errors.New("Error when getting caller of the request"))
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error if ctx.GetCaller returns error")
	if err != nil {
		assert.Contains(t, err.Error(), "Error when getting caller of the request")
	}
}

func TestHandleIdemixEnrollCheckNonceError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			tstHandleIdemixEnrollCheckNonceError(t, curve)
		})
	}
}

func tstHandleIdemixEnrollCheckNonceError(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)

	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}

	rmo := curve.NewRandomZr(rand)
	rmo.Mod(curve.GroupOrder)

	idemixlib.On("GetRand").Return(rand, nil)
	idemixlib.On("RandModOrder", rand).Return(rmo)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib, curveID)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}

	rh := curve.NewZrFromInt(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rand)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer, CurveID: curveID, Curve: curve, Translator: cidemix.InstanceForCurve(curveID).Translator}
	nm := new(mocks.NonceManager)
	nonce := curve.NewRandomZr(rand)
	nonce.Mod(curve.GroupOrder)

	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(errors.New("Invalid nonce"))
	issuer.On("NonceManager").Return(nm)

	caller := new(mocks.User)
	caller.On("Name").Return("foo")

	credReq, _, err := newIdemixCredentialRequest(t, nonce, curveID, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error because NonceManager.CheckNonce returned error")
}

func TestHandleIdemixEnrollNewCredError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testHandleIdemixEnrollNewCredError(t, curve)
		})
	}
}

func testHandleIdemixEnrollNewCredError(t *testing.T, curveID cidemix.CurveID) {
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	curve := cidemix.CurveByID(curveID)
	rnd, err := curve.Rand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := curve.NewRandomZr(rnd)
	rmo.Mod(curve.GroupOrder)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib, curveID)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, _ := issuerCred.GetIssuerKey()

	rh := curve.NewZrFromInt(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rnd)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer, CurveID: curveID, Curve: curve, Translator: cidemix.InstanceForCurve(curveID).Translator}
	nm := new(mocks.NonceManager)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Failed to create randomness source")
	}

	nonce := curve.NewRandomZr(rand)
	nonce.Mod(curve.GroupOrder)

	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(nil)
	issuer.On("NonceManager").Return(nm)

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _, err := newIdemixCredentialRequest(t, nonce, curveID, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	_, attrs, err := handler.GetAttributeValues(caller, ik.Ipk, rh)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}

	idemixlib.On("NewCredential", ik, credReq, attrs).Return(nil, errors.New("Failed to create credential"))

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error because idemix.NewCredential returned error")
}

func TestHandleIdemixEnrollInsertCredError(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testHandleIdemixEnrollInsertCredError(t, curve)
		})
	}
}

func testHandleIdemixEnrollInsertCredError(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Failed to create randomness source")
	}

	rmo := curve.NewRandomZr(rand)
	rmo.Mod(curve.GroupOrder)

	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	idemixlib.On("RandModOrder", rmo).Return(rmo)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib, curveID)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, _ := issuerCred.GetIssuerKey()

	rh := curve.NewZrFromInt(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer, CurveID: curveID, Curve: curve, Translator: cidemix.InstanceForCurve(curveID).Translator}
	nm := new(mocks.NonceManager)

	nonce := curve.NewRandomZr(rand)
	nonce.Mod(curve.GroupOrder)

	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(nil)

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _, err := newIdemixCredentialRequest(t, nonce, curveID, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	_, attrs, err := handler.GetAttributeValues(caller, ik.Ipk, rh)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}

	cred, err := cidemix.InstanceForCurve(curveID).NewCredential(ik, credReq, attrs, rand, cidemix.InstanceForCurve(curveID).Translator)
	if err != nil {
		t.Fatalf("Failed to create credential: %v", err)
	}
	idemixlib.On("NewCredential", ik, credReq, attrs).Return(cred, nil)

	b64CredBytes, err := getB64EncodedCred(cred)
	if err != nil {
		t.Fatalf("Failed to base64 encode credential")
	}
	credAccessor := new(mocks.CredDBAccessor)
	credAccessor.On("InsertCredential",
		CredRecord{
			RevocationHandle: util.B64Encode(curve.NewZrFromInt(1).Bytes()),
			CALabel:          "", ID: "foo", Status: "good",
			Cred: b64CredBytes,
		}).Return(errors.New("Failed to add credential to DB"))

	issuer.On("CredDBAccessor").Return(credAccessor, nil)
	issuer.On("NonceManager").Return(nm)

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error because CredDBAccessor.InsertCredentail returned error")
}

func TestHandleIdemixEnrollForCredentialSuccess(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testHandleIdemixEnrollForCredentialSuccess(t, curve)
		})
	}
}

func testHandleIdemixEnrollForCredentialSuccess(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)
	rand, err := curve.Rand()
	if err != nil {
		t.Fatalf("Failed to create randomness source")
	}

	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	rmo := curve.NewRandomZr(rand)
	rmo.Mod(curve.GroupOrder)

	idemixlib.On("GetRand").Return(rand, nil)
	idemixlib.On("RandModOrder", rand).Return(rmo)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t, curveID)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib, curveID)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, _ := issuerCred.GetIssuerKey()

	rh := curve.NewZrFromInt(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rand)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer, CurveID: curveID, Curve: curve, Translator: cidemix.InstanceForCurve(curveID).Translator}
	nm := new(mocks.NonceManager)

	nonce := curve.NewRandomZr(rand)
	nonce.Mod(curve.GroupOrder)
	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(nil)

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _, err := newIdemixCredentialRequest(t, nonce, curveID, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	_, attrs, err := handler.GetAttributeValues(caller, ik.Ipk, rh)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}

	idemix := cidemix.InstanceForCurve(curveID)

	cred, err := idemix.NewCredential(ik, credReq, attrs, rand, idemix.Translator)
	if err != nil {
		t.Fatalf("Failed to create credential: %v", err)
	}
	idemixlib.On("NewCredential", ik, credReq, attrs).Return(cred, nil)

	b64CredBytes, err := getB64EncodedCred(cred)
	if err != nil {
		t.Fatalf("Failed to base64 encode credential")
	}
	credAccessor := new(mocks.CredDBAccessor)
	credAccessor.On("InsertCredential", CredRecord{
		RevocationHandle: util.B64Encode(curve.NewZrFromInt(1).Bytes()),
		CALabel:          "", ID: "foo", Status: "good", Cred: b64CredBytes,
	}).Return(nil)

	issuer.On("CredDBAccessor").Return(credAccessor, nil)
	issuer.On("NonceManager").Return(nm)

	cri, err := createCRI(t, curveID)
	if err != nil {
		t.Fatalf("Failed to create CRI: %s", err.Error())
	}
	ra.On("CreateCRI").Return(cri, nil)

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.NoError(t, err)
}

func TestGetAttributeValues(t *testing.T) {
	for _, curve := range cidemix.Curves {
		t.Run(fmt.Sprintf("%s-%d", t.Name(), curve), func(t *testing.T) {
			testGetAttributeValues(t, curve)
		})
	}
}

func testGetAttributeValues(t *testing.T, curveID cidemix.CurveID) {
	curve := cidemix.CurveByID(curveID)

	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, CurveID: curveID, Curve: curve, Translator: cidemix.InstanceForCurve(curveID).Translator}

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("GetAttribute", "type").Return(&api.Attribute{Name: "type", Value: "client"}, nil)
	caller.On("LoginComplete").Return(nil)

	rh := curve.NewZrFromInt(1)

	attrNames := GetAttributeNames()
	attrNames = append(attrNames, "type")
	ipk := idemix.IssuerPublicKey{AttributeNames: attrNames}
	_, _, err := handler.GetAttributeValues(caller, &ipk, rh)
	assert.NoError(t, err)
}

func createCRI(t *testing.T, curveID cidemix.CurveID) (*idemix.CredentialRevocationInformation, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	curve := cidemix.CurveByID(curveID)

	rnd, err := curve.Rand()
	if err != nil {
		return nil, err
	}

	idemixInstance := cidemix.InstanceForCurve(curveID)

	return idemixInstance.CreateCRI(key, []*math.Zr{}, 1, idemix.ALG_NO_REVOCATION, rnd, idemixInstance.Translator)
}

func getB64EncodedCred(cred *idemix.Credential) (string, error) {
	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return "", errors.New("Failed to marshal credential to bytes")
	}
	b64CredBytes := util.B64Encode(credBytes)
	return b64CredBytes, nil
}

func getReadBodyFunc(t *testing.T, credReq *idemix.CredRequest) func(body interface{}) error {
	return func(body interface{}) error {
		enrollReq, _ := body.(*api.IdemixEnrollmentRequestNet)
		if credReq == nil {
			return errors.New("Error reading the body")
		}
		enrollReq.CredRequest = credReq
		return nil
	}
}

func newIdemixCredentialRequest(t *testing.T, nonce *math.Zr, curveID cidemix.CurveID, testPublicKeyFile, testSecretKeyFile string) (*idemix.CredRequest, *math.Zr, error) {
	idmxlib := new(mocks.Lib)
	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idmxlib, curveID)
	err := issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, err := issuerCred.GetIssuerKey()
	if err != nil {
		t.Fatalf("Issuer credential returned error while getting issuer key")
	}
	curve := cidemix.InstanceForCurve(curveID).Curve

	rand, err := curve.Rand()
	if err != nil {
		return nil, nil, err
	}

	sk := curve.NewRandomZr(rand)
	sk.Mod(curve.GroupOrder)

	idemix := cidemix.InstanceForCurve(curveID)

	credReq, err := idemix.NewCredRequest(sk, nonce.Bytes(), ik.Ipk, rand, idemix.Translator)
	return credReq, sk, err
}
