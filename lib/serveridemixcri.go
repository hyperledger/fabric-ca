/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/cloudflare/cfssl/log"
)

func newIdemixCRIEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Path:      "idemix/cri",
		Methods:   []string{"POST"},
		Handler:   handleIdemixCRIReq,
		Server:    s,
		successRC: 201,
	}
}

// handleIdemixCRIReq handles an Idemix cri request
func handleIdemixCRIReq(ctx *serverRequestContextImpl) (interface{}, error) {
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}

	idemixcriResp, err := ca.issuer.GetCRI(&idemixServerCtx{ctx})
	if err != nil {
		log.Errorf("Error processing the /idemix/cri request: %s", err.Error())
		return nil, err
	}
	return idemixcriResp, nil
}
