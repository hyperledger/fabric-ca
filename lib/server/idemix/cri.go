/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

// CRIRequestHandler is the handler for Idemix CRI (credential revocation information) request
type CRIRequestHandler struct {
	Ctx    ServerRequestCtx
	Issuer *IssuerInst
}

// HandleRequest handles processing for idemix/cri request
func (ch *CRIRequestHandler) HandleRequest() (*api.GetCRIResponse, error) {
	_, err := ch.Ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}

	cri, err := ch.Issuer.RevocationAuthority.CreateCRI()
	if err != nil {
		return nil, err
	}

	b64CriBytes := util.B64Encode(cri)
	res := api.GetCRIResponse{
		CRI: b64CriBytes,
	}
	return &res, nil
}
