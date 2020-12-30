/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/hyperledger/fabric-ca/internal/pkg/api"
	"github.com/hyperledger/fabric-ca/lib/metadata"
)

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
	resp := &api.CAInfoResponseNet{}
	err = ca.fillCAInfo(resp)
	if err != nil {
		return nil, err
	}
	resp.Version = metadata.GetVersion()
	return resp, nil
}
