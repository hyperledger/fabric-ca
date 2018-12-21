/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/hyperledger/fabric-ca/lib/common"
	"github.com/hyperledger/fabric-ca/lib/metadata"
)

// ServerInfoResponseNet is the response to the GET /cainfo request
type ServerInfoResponseNet struct {
	// CAName is a unique name associated with fabric-ca-server's CA
	CAName string
	// Base64 encoding of PEM-encoded certificate chain
	CAChain string
	// Base64 encoding of idemix issuer public key
	IssuerPublicKey string
	// Version of the server
	Version string
}

func newCAInfoEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:    "cainfo",
		Methods: []string{"GET", "POST", "HEAD"},
		Handler: cainfoHandler,
		Server:  s,
	}
}

// Handle is the handler for the GET or POST /cainfo request
func cainfoHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	resp := &common.CAInfoResponseNet{}
	err = ca.fillCAInfo(resp)
	if err != nil {
		return nil, err
	}
	resp.Version = metadata.GetVersion()
	return resp, nil
}
