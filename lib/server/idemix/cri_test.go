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

	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestCRIInvalidTokenAuth(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", errors.New("bad credentials"))
	handler := CRIRequestHandler{Ctx: ctx}
	_, err := handler.HandleRequest()
	assert.Error(t, err, "Idemix CRI should fail if token auth credentials are invalid")
}

func TestCreateCRIError(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", nil)
	issuer := new(mocks.MyIssuer)
	ra := new(mocks.RevocationAuthority)
	ra.On("CreateCRI").Return(nil, errors.New("Failed to create CRI"))
	issuer.On("RevocationAuthority").Return(ra)
	handler := CRIRequestHandler{Ctx: ctx, Issuer: issuer}
	_, err := handler.HandleRequest()
	assert.Error(t, err)
}

func TestGetCRIMarshalError(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", nil)
	issuer := new(mocks.MyIssuer)
	ra := new(mocks.RevocationAuthority)
	ra.On("CreateCRI").Return(nil, nil)
	issuer.On("RevocationAuthority").Return(ra)
	handler := CRIRequestHandler{Ctx: ctx, Issuer: issuer}
	_, err := handler.HandleRequest()
	assert.Error(t, err, "GetCRI should have failed when marshalling idemix.CredentialRevocationInformation")
}

func TestGetCRI(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", nil)
	issuer := new(mocks.MyIssuer)
	ra := new(mocks.RevocationAuthority)
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create ecdsa key: %s", err.Error())
	}
	rnd, err := idemix.GetRand()
	if err != nil {
		t.Fatalf("Failed generate random number: %s", err.Error())
	}
	cri, err := idemix.CreateCRI(privateKey, []*fp256bn.BIG{}, 1, idemix.ALG_NO_REVOCATION, rnd)
	if err != nil {
		t.Fatalf("Failed to create CRI: %s", err.Error())
	}
	ra.On("CreateCRI").Return(cri, nil)
	issuer.On("RevocationAuthority").Return(ra)
	handler := CRIRequestHandler{Ctx: ctx, Issuer: issuer}
	_, err = handler.HandleRequest()
	assert.NoError(t, err)
}
