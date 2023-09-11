/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix_test

import (
	"testing"

	"github.com/IBM/idemix/bccsp/types"
	bccsp "github.com/IBM/idemix/bccsp/types"
	ibccsp "github.com/IBM/idemix/bccsp/types"
	. "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/idemix/mocks"
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
	issuer := new(IssuerInst)
	ra := new(mocks.RevocationAuthority)
	ra.On("CreateCRI").Return(nil, errors.New("Failed to create CRI"))
	issuer.RevocationAuthority = ra
	handler := CRIRequestHandler{Ctx: ctx, Issuer: issuer}
	_, err := handler.HandleRequest()
	assert.Error(t, err)
}

func TestGetCRI(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", nil)
	issuer := new(IssuerInst)
	ra := new(mocks.RevocationAuthority)

	RevocationKey, err := getCSP(t).KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	assert.NoError(t, err)

	cri, err := getCSP(t).Sign(
		RevocationKey,
		nil,
		&ibccsp.IdemixCRISignerOpts{
			UnrevokedHandles:    nil,
			Epoch:               1,
			RevocationAlgorithm: types.AlgNoRevocation,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create CRI: %s", err.Error())
	}
	ra.On("CreateCRI").Return(cri, nil)
	issuer.RevocationAuthority = ra
	handler := CRIRequestHandler{Ctx: ctx, Issuer: issuer}
	_, err = handler.HandleRequest()
	assert.NoError(t, err)
}
