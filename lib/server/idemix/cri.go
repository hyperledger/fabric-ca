/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// CRIRequestHandler is the handler for Idemix CRI (credential revocation information) request
type CRIRequestHandler struct {
	Ctx    ServerRequestCtx
	Issuer MyIssuer
}

// HandleRequest handles processing for idemix/cri request
func (ch *CRIRequestHandler) HandleRequest() (*api.GetCRIResponse, error) {
	_, err := ch.Ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}

	cri, err := ch.Issuer.RevocationAuthority().CreateCRI()
	if err != nil {
		return nil, err
	}
	criBytes, err := proto.Marshal(cri)
	if err != nil {
		return nil, errors.New("Failed to marshal Idemix credential to bytes")
	}
	b64CriBytes := util.B64Encode(criBytes)
	res := api.GetCRIResponse{
		CRI: b64CriBytes,
	}
	return &res, nil
}
