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
	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
)

type signingCertResponseNet struct {
	api.SigningCert
}

func newSigningCertEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"POST"},
		Handler:   signingCertHandler,
		Server:    s,
		successRC: 200,
	}
}

// Handle an signingCert request
func signingCertHandler(ctx *serverRequestContext) (interface{}, error) {
	// Parse signingCert request body
	var req api.SigningCertRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Authentication
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}

	log.Debugf("Authentication successful: %s", id)

	// Get targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	certDBAccessor := ca.certDBAccessor
	registry := ca.registry

	result := &signingCertResponseNet{}
	if req.Name != "" {

		user, err := registry.GetUser(req.Name, nil)
		if err != nil {
			return nil, newHTTPErr(404, ErrSigningCertIDNotFound, "Identity %s was not found: %s", req.Name, err)
		}

		log.Debugf("User found: %+v", user)

		var recs []CertRecord
		recs, err = certDBAccessor.GetCertificatesByID(req.Name)
		if err != nil {
			return nil, newHTTPErr(500, ErrNoSigningCertsFound, "Failed to find certificates for '%s': %s",
				req.Name, err)
		}

		if len(recs) == 0 {
			return nil, newHTTPErr(404, ErrNoSigningCertsFound, "Failed to find certificates for '%s': %s",
				req.Name)
		} else {
			for _, certRec := range recs {
				if certRec.Status == Good {
					result.Cert = certRec.CertificateRecord.PEM

				}
			}
		}
	} else {
		return nil, newHTTPErr(400, ErrMissingSigningCertArgs, "Name is required for a signingCert request")
	}

	log.Debugf("SigningCert was successful: %+v", req)

	return result, nil
}
