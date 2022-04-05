/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	proto "github.com/golang/protobuf/proto"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
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
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)
	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)
	ctx.On("IsBasicAuth").Return(true)
	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("IdemixRand").Return(rnd)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(fp256bn.NewBIG(), nil)
	issuer.On("NonceManager").Return(nm)
	handler := EnrollRequestHandler{Ctx: ctx, Issuer: issuer, IdmxLib: idemixlib}
	_, err = handler.HandleRequest()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}
func TestHandleIdemixEnrollForNonceTokenAuth(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)

	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	ctx.On("IsBasicAuth").Return(false)

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("IdemixRand").Return(rnd)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(fp256bn.NewBIG(), nil)
	issuer.On("NonceManager").Return(nm)

	ctx.On("GetIssuer").Return(issuer, nil)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	_, err = handler.HandleRequest()
	assert.NoError(t, err, "Idemix enroll should return a valid nonce")
}

func TestHandleIdemixEnrollForNonceError(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("foo", nil)

	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	ctx.On("IsBasicAuth").Return(false)

	req := api.IdemixEnrollmentRequestNet{}
	req.CredRequest = nil
	ctx.On("ReadBody", &req).Return(nil)
	issuer := new(mocks.MyIssuer)
	issuer.On("IdemixRand").Return(rnd)

	nm := new(mocks.NonceManager)
	nm.On("GetNonce").Return(nil, errors.New("Failed to generate nonce"))
	issuer.On("NonceManager").Return(nm)

	ctx.On("GetIssuer").Return(issuer, nil)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	_, err = handler.HandleRequest()
	assert.Error(t, err, "Idemix enroll should return an error because NonceManager.GetNonce returned an error")
}

func TestHandleIdemixEnrollForCredentialError(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("BasicAuthentication").Return("foo", nil)

	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo, nil)

	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idemixlib)
	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rnd)

	ctx.On("GetIssuer").Return(issuer, nil)
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	nonce, err := handler.GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %s", err.Error())
	}

	credReq, _, err := newIdemixCredentialRequest(t, nonce)
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
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}

	rh := fp256bn.NewBIGint(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rnd)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	nm := new(mocks.NonceManager)
	nonce := idemix.RandModOrder(rnd)
	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(errors.New("Invalid nonce"))
	issuer.On("NonceManager").Return(nm)

	caller := new(mocks.User)
	caller.On("Name").Return("foo")

	credReq, _, err := newIdemixCredentialRequest(t, nonce)
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
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, _ := issuerCred.GetIssuerKey()

	rh := fp256bn.NewBIGint(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rnd)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	nm := new(mocks.NonceManager)
	nonce := idemix.RandModOrder(rnd)
	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(nil)
	issuer.On("NonceManager").Return(nm)

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _, err := newIdemixCredentialRequest(t, nonce)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	_, attrs, err := handler.GetAttributeValues(caller, ik.Ipk, rh)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}

	idemixlib.On("NewCredential", ik, credReq, attrs, rnd).Return(nil, errors.New("Failed to create credential"))

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
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, _ := issuerCred.GetIssuerKey()

	rh := fp256bn.NewBIGint(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rnd)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	nm := new(mocks.NonceManager)
	nonce := idemix.RandModOrder(rnd)
	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(nil)

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _, err := newIdemixCredentialRequest(t, nonce)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	_, attrs, err := handler.GetAttributeValues(caller, ik.Ipk, rh)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}
	cred, err := idemix.NewCredential(ik, credReq, attrs, rnd)
	if err != nil {
		t.Fatalf("Failed to create credential")
	}
	idemixlib.On("NewCredential", ik, credReq, attrs, rnd).Return(cred, nil)

	b64CredBytes, err := getB64EncodedCred(cred)
	if err != nil {
		t.Fatalf("Failed to base64 encode credential")
	}
	credAccessor := new(mocks.CredDBAccessor)
	credAccessor.On("InsertCredential",
		CredRecord{RevocationHandle: util.B64Encode(idemix.BigToBytes(fp256bn.NewBIGint(1))),
			CALabel: "", ID: "foo", Status: "good",
			Cred: b64CredBytes}).Return(errors.New("Failed to add credential to DB"))

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
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Error generating a random number")
	}
	rmo := idemix.RandModOrder(rnd)
	idemixlib.On("GetRand").Return(rnd, nil)
	idemixlib.On("RandModOrder", rnd).Return(rmo)

	issuerCred := NewIssuerCredential(testPublicKeyFile,
		testSecretKeyFile, idemixlib)
	err = issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, _ := issuerCred.GetIssuerKey()

	rh := fp256bn.NewBIGint(1)
	ra := new(mocks.RevocationAuthority)
	ra.On("GetNewRevocationHandle").Return(rh, nil)

	issuer := new(mocks.MyIssuer)
	issuer.On("Name").Return("")
	issuer.On("IssuerCredential").Return(issuerCred)
	issuer.On("IdemixRand").Return(rnd)
	issuer.On("RevocationAuthority").Return(ra)

	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib, Issuer: issuer}
	nm := new(mocks.NonceManager)
	nonce := idemix.RandModOrder(rnd)
	nm.On("GetNonce").Return(nonce, nil)
	nm.On("CheckNonce", nonce).Return(nil)

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("LoginComplete").Return(nil)

	credReq, _, err := newIdemixCredentialRequest(t, nonce)
	if err != nil {
		t.Fatalf("Failed to create test credential request")
	}
	_, attrs, err := handler.GetAttributeValues(caller, ik.Ipk, rh)
	if err != nil {
		t.Fatalf("Failed to get attributes")
	}
	cred, err := idemix.NewCredential(ik, credReq, attrs, rnd)
	if err != nil {
		t.Fatalf("Failed to create credential")
	}
	idemixlib.On("NewCredential", ik, credReq, attrs, rnd).Return(cred, nil)

	b64CredBytes, err := getB64EncodedCred(cred)
	if err != nil {
		t.Fatalf("Failed to base64 encode credential")
	}
	credAccessor := new(mocks.CredDBAccessor)
	credAccessor.On("InsertCredential", CredRecord{
		RevocationHandle: util.B64Encode(idemix.BigToBytes(fp256bn.NewBIGint(1))),
		CALabel:          "", ID: "foo", Status: "good", Cred: b64CredBytes}).Return(nil)

	issuer.On("CredDBAccessor").Return(credAccessor, nil)
	issuer.On("NonceManager").Return(nm)

	cri, err := createCRI(t)
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
	ctx := new(mocks.ServerRequestCtx)
	idemixlib := new(mocks.Lib)
	ctx.On("IsBasicAuth").Return(true)
	handler := EnrollRequestHandler{Ctx: ctx, IdmxLib: idemixlib}

	caller := new(mocks.User)
	caller.On("GetName").Return("foo")
	caller.On("GetAffiliationPath").Return([]string{"a", "b", "c"})
	caller.On("GetAttribute", "role").Return(&api.Attribute{Name: "role", Value: "2"}, nil)
	caller.On("GetAttribute", "type").Return(&api.Attribute{Name: "type", Value: "client"}, nil)
	caller.On("LoginComplete").Return(nil)

	rh := fp256bn.NewBIGint(1)

	attrNames := GetAttributeNames()
	attrNames = append(attrNames, "type")
	ipk := idemix.IssuerPublicKey{AttributeNames: attrNames}
	_, _, err := handler.GetAttributeValues(caller, &ipk, rh)
	assert.NoError(t, err)
}

func createCRI(t *testing.T) (*idemix.CredentialRevocationInformation, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rnd, err := idemix.GetRand()
	if err != nil {
		return nil, err
	}
	return idemix.CreateCRI(key, []*fp256bn.BIG{}, 1, idemix.ALG_NO_REVOCATION, rnd)
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

func newIdemixCredentialRequest(t *testing.T, nonce *fp256bn.BIG) (*idemix.CredRequest, *fp256bn.BIG, error) {
	idmxlib := new(mocks.Lib)
	issuerCred := NewIssuerCredential(testPublicKeyFile, testSecretKeyFile, idmxlib)
	err := issuerCred.Load()
	if err != nil {
		t.Fatalf("Failed to load issuer credential")
	}
	ik, err := issuerCred.GetIssuerKey()
	if err != nil {
		t.Fatalf("Issuer credential returned error while getting issuer key")
	}
	rng, err := idemix.GetRand()
	if err != nil {
		return nil, nil, err
	}
	sk := idemix.RandModOrder(rng)
	return idemix.NewCredRequest(sk, idemix.BigToBytes(nonce), ik.Ipk, rng), sk, nil
}
