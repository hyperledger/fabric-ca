/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package lib

import (
	"github.com/hyperledger/fabric-ca/api"
	tcert "github.com/hyperledger/fabric-ca/lib/tcert"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

func newTCertEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: tcertHandler,
		Server:  s,
	}
}

// Handle a tcert request
func tcertHandler(ctx *serverRequestContext) (interface{}, error) {
	// Authenticate caller
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	// Read request body
	req := &api.GetTCertBatchRequestNet{}
	err = ctx.ReadBody(req)
	if err != nil {
		return nil, err
	}
	// Get the targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Get requested attribute values for caller and affiliation path
	caller, err := ctx.GetCaller()
	if err != nil {
		return nil, err
	}
	attrs, err := caller.GetAttributes(req.AttrNames)
	if err != nil {
		return nil, errors.Errorf("Failed to get attributes '%s': %s", req.AttrNames, err)
	}
	affiliationPath := caller.GetAffiliationPath()
	// Get the prekey associated with the affiliation path
	prekey, err := ca.keyTree.GetKey(affiliationPath)
	if err != nil {
		return nil, newHTTPErr(500, ErrNoPreKey, "Failed to get prekey for identity %s: %s", id, err)
	}
	// TODO: When the TCert library is based on BCCSP, we will pass the prekey
	//       directly.  Converting the SKI to a string is a temporary kludge
	//       which isn't correct.
	prekeyStr := string(prekey.SKI())
	// Call the tcert library to get the batch of tcerts
	tcertReq := &tcert.GetTCertBatchRequest{}
	tcertReq.Count = req.Count
	tcertReq.Attrs = attrs
	tcertReq.EncryptAttrs = req.EncryptAttrs
	tcertReq.ValidityPeriod = req.ValidityPeriod
	tcertReq.PreKey = prekeyStr
	resp, err := ca.tcertMgr.GetBatch(tcertReq, ctx.GetECert())
	if err != nil {
		return nil, err
	}
	// Successful response
	return resp, nil
}

// genRootKey generates a new root key
func genRootKey(csp bccsp.BCCSP) (bccsp.Key, error) {
	opts := &bccsp.AES256KeyGenOpts{Temporary: true}
	return csp.KeyGen(opts)
}
