/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"crypto/rand"
	"os"
	"testing"

	bccsp "github.com/IBM/idemix/bccsp/types"
	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	idemixlib := new(mocks.BccspBCCSP)

	ctx.On("IsBasicAuth").Return(true)
	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)

	issuer := new(IssuerInst)

	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	assert.NoError(t, err)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(nonceBytes, nil)
	issuer.NonceManager = nm
	handler := EnrollRequestHandler{Ctx: ctx, Issuer: issuer, CSP: idemixlib}
	_, err = handler.HandleRequest()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForNonceTokenAuth(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)

	idemixlib := new(mocks.BccspBCCSP)
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	assert.NoError(t, err)

	ctx.On("IsBasicAuth").Return(false)

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	issuer := new(IssuerInst)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(nonceBytes, nil)
	issuer.NonceManager = nm

	ctx.On("GetIssuer").Return(issuer, nil)
	handler := EnrollRequestHandler{Ctx: ctx, CSP: idemixlib, Issuer: issuer}
	_, err = handler.HandleRequest()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForNonceError(t *testing.T) {

	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)

	idemixlib := new(mocks.BccspBCCSP)

	ctx.On("IsBasicAuth").Return(false)

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	issuer := new(IssuerInst)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(nil, errors.New("Failed to generate nonce"))
	issuer.NonceManager = nm

	ctx.On("GetIssuer").Return(issuer, nil)
	handler := EnrollRequestHandler{Ctx: ctx, CSP: idemixlib, Issuer: issuer}
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return an error because NonceManager.GetNonce returned an error")
}

func TestHandleIdemixEnrollForCredentialError(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)

	idemixlib := getCSP(t)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixlib)
	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.IssuerCred = issuerCred

	ctx.On("GetIssuer").Return(issuer, nil)
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, CSP: idemixlib, Issuer: issuer}
	nonce, err := handler.GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %s", err.Error())
	}

	credReq, _ := newIdemixCredentialRequest(t, nonce, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create credential request: %s", err.Error())
	}
	f := getReadBodyFunc(t, credReq, nonce)
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
	ctx := new(mocks.ServerRequestCtx)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, getCSP(t))
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}

	rh := int64(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.IssuerCred = issuerCred
	issuer.RevocationAuthority = ra

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, CSP: getCSP(t), Issuer: issuer}
	nm := new(mocks.NonceManager)
	nonceBytes := make([]byte, 32)
	_, err = rand.Read(nonceBytes)
	assert.NoError(t, err)

	nm.On("GetNonce").Return(nonceBytes, nil)
	nm.On("CheckNonce", nonceBytes).Return(errors.New("Invalid nonce"))
	issuer.NonceManager = nm

	caller := new(mocks.UserUser)
	caller.On("Name").Return("foo")

	credReq, _ := newIdemixCredentialRequest(t, nonceBytes, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq, nonceBytes)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error because NonceManager.CheckNonce returned error")
}

func TestHandleIdemixEnrollNewCredError(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, getCSP(t))
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}

	rh := int64(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.IssuerCred = issuerCred
	issuer.RevocationAuthority = ra

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, CSP: getCSP(t), Issuer: issuer}
	nm := new(mocks.NonceManager)

	nonceBytes := make([]byte, 32)
	_, err = rand.Read(nonceBytes)
	assert.NoError(t, err)

	nm.On("GetNonce").Return(nonceBytes, nil)
	nm.On("CheckNonce", nonceBytes).Return(nil)
	issuer.NonceManager = nm

	caller := new(mocks.UserUser)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _ := newIdemixCredentialRequest(t, nonceBytes, testPublicKeyFile, testSecretKeyFile)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq, nonceBytes)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	mockCsp := new(mocks.BccspBCCSP)
	mockCsp.On("Verify", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	mockCsp.On("Sign", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("error error"))
	handler.CSP = mockCsp

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error because idemix.NewCredential returned error")
}

func TestHandleIdemixEnrollInsertCredError(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, getCSP(t))
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	isk, _ := issuerCred.GetIssuerKey()

	rh := int64(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.IssuerCred = issuerCred
	issuer.RevocationAuthority = ra

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, Issuer: issuer}
	nm := new(mocks.NonceManager)

	nonceBytes := make([]byte, 32)
	_, err = rand.Read(nonceBytes)
	assert.NoError(t, err)

	nm.On("GetNonce").Return(nonceBytes, nil)
	nm.On("CheckNonce", nonceBytes).Return(nil)

	caller := new(mocks.UserUser)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _ := newIdemixCredentialRequest(t, nonceBytes, testPublicKeyFile, testSecretKeyFile)
	attrs, _, err := handler.GetAttributeValues(caller, GetAttributeNames(), int64(rh))
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}

	cred, err := getCSP(t).Sign(
		isk,
		credReq,
		&bccsp.IdemixCredentialSignerOpts{
			Attributes: attrs,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create credential: %v", err)
	}

	b64CredBytes, err := getB64EncodedCred(cred)
	if err != nil {
		t.Fatalf("Failed to base64 encode credential")
	}
	credAccessor := new(mocks.CredDBAccessor)
	credAccessor.On("InsertCredential",
		CredRecord{
			RevocationHandle: "1",
			CALabel:          "", ID: "foo", Status: "good",
			Cred: b64CredBytes,
		}).Return(errors.New("Failed to add credential to DB"))

	issuer.CredDBAccessor = credAccessor
	issuer.NonceManager = nm

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq, nonceBytes)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	mockcsp := new(mocks.BccspBCCSP)
	handler.CSP = mockcsp
	mockcsp.On("Verify", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	mockcsp.On("Sign", mock.Anything, mock.Anything, mock.Anything).Return(cred, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return error because CredDBAccessor.InsertCredentail returned error")
}

func TestHandleIdemixEnrollForCredentialSuccess(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := getCSP(t)

	testPublicKeyFile, testSecretKeyFile, tmpDir, err := GeneratePublicPrivateKeyPair(t)
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	isk, _ := issuerCred.GetIssuerKey()

	rh := int64(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(IssuerInst)
	issuer.Name = ""
	issuer.IssuerCred = issuerCred
	issuer.RevocationAuthority = ra

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, CSP: idemixlib, Issuer: issuer}
	nm := new(mocks.NonceManager)

	nonceBytes := make([]byte, 32)
	_, err = rand.Read(nonceBytes)
	assert.NoError(t, err)

	nm.On("GetNonce").Return(nonceBytes, nil)
	nm.On("CheckNonce", nonceBytes).Return(nil)

	caller := new(mocks.UserUser)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _ := newIdemixCredentialRequest(t, nonceBytes, testPublicKeyFile, testSecretKeyFile)
	attrs, _, err := handler.GetAttributeValues(caller, GetAttributeNames(), 1)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}

	cred, err := getCSP(t).Sign(
		isk,
		credReq,
		&bccsp.IdemixCredentialSignerOpts{
			Attributes: attrs,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create credential: %v", err)
	}

	b64CredBytes, err := getB64EncodedCred(cred)
	if err != nil {
		t.Fatalf("Failed to base64 encode credential")
	}
	credAccessor := new(mocks.CredDBAccessor)
	credAccessor.On("InsertCredential", CredRecord{
		RevocationHandle: "1", ID: "foo", Status: "good", Cred: b64CredBytes,
	}).Return(nil)

	issuer.CredDBAccessor = credAccessor
	issuer.NonceManager = nm

	cri, err := createCRI(t)
	if err != nil {
		t.Fatalf("Failed to create CRI: %s", err.Error())
	}
	ra.On("CreateCRI").Return(cri, nil)

	ctx.On("BasicAuthentication").Return("foo", nil)
	f := getReadBodyFunc(t, credReq, nonceBytes)
	ctx.On("ReadBody", &api.IdemixEnrollmentRequestNet{}).Return(f)
	ctx.On("GetCA").Return(issuer, nil)
	ctx.On("GetCaller").Return(caller, nil)

	mockcsp := new(mocks.BccspBCCSP)
	handler.CSP = mockcsp
	mockcsp.On("Verify", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	mockcsp.On("Sign", mock.Anything, mock.Anything, mock.Anything).Return(cred, nil)

	// Now setup of all mocks is over, test the method
	_, err = handler.HandleRequest()
	assert.NoError(t, err)
}

func TestGetAttributeValues(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.BccspBCCSP)
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, CSP: idemixlib}

	caller := new(mocks.UserUser)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("GetAttribute", "type").Return(&api.Attribute{Name: "type", Value: "client"}, nil)
	caller.On("LoginComplete").Return(nil)

	_, _, err := handler.GetAttributeValues(caller, GetAttributeNames(), 1)
	assert.NoError(t, err)
}
