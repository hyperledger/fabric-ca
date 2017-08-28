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
	"strings"

	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
)

func newRevokeEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: revokeHandler,
		Server:  s,
	}
}

// Handle an revoke request
func revokeHandler(ctx *serverRequestContext) (interface{}, error) {
	// Parse revoke request body
	var req api.RevocationRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Authentication
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	// Get targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Authorization
	// Make sure that the caller has the "hf.Revoker" attribute.
	err = ca.attributeIsTrue(id, "hf.Revoker")
	if err != nil {
		return nil, newHTTPErr(401, ErrNotRevoker, "Caller does not have authority to revoke")
	}

	req.AKI = strings.TrimLeft(strings.ToLower(req.AKI), "0")
	req.Serial = strings.TrimLeft(strings.ToLower(req.Serial), "0")

	certDBAccessor := ca.certDBAccessor
	registry := ca.registry
	reason := util.RevocationReasonCodes[req.Reason]

	if req.Serial != "" && req.AKI != "" {
		certificate, err := certDBAccessor.GetCertificateWithID(req.Serial, req.AKI)
		if err != nil {
			return nil, newHTTPErr(404, ErrRevCertNotFound, "Certificate with serial %s and AKI %s was not found: %s",
				req.Serial, req.AKI, err)
		}

		if req.Name != "" && req.Name != certificate.ID {
			return nil, newHTTPErr(400, ErrCertWrongOwner, "Certificate with serial %s and AKI %s is not owned by %s",
				req.Serial, req.AKI, req.Name)
		}

		userInfo, err := registry.GetUserInfo(certificate.ID)
		if err != nil {
			return nil, newHTTPErr(404, ErrRevokeIDNotFound, "Identity %s was not found: %s", certificate.ID, err)
		}

		err = checkAffiliations(id, userInfo, ca)
		if err != nil {
			return nil, err
		}

		err = certDBAccessor.RevokeCertificate(req.Serial, req.AKI, reason)
		if err != nil {
			return nil, newHTTPErr(500, ErrRevokeFailure, "Revoke of certificate <%s,%s> failed: %s", req.Serial, req.AKI, err)
		}
	} else if req.Name != "" {

		user, err := registry.GetUser(req.Name, nil)
		if err != nil {
			return nil, newHTTPErr(404, ErrRevokeIDNotFound, "Identity %s was not found: %s", req.Name, err)
		}

		// Set user state to -1 for revoked user
		if user != nil {
			var userInfo spi.UserInfo
			userInfo, err = registry.GetUserInfo(req.Name)
			if err != nil {
				return nil, newHTTPErr(500, ErrRevokeUserInfoNotFound, "Failed getting info for identity %s: %s", req.Name, err)
			}

			err = checkAffiliations(id, userInfo, ca)
			if err != nil {
				return nil, err
			}

			userInfo.State = -1

			err = registry.UpdateUser(userInfo)
			if err != nil {
				return nil, newHTTPErr(500, ErrRevokeUpdateUser, "Failed to update identity info: %s", err)
			}
		}

		var recs []CertRecord
		recs, err = certDBAccessor.RevokeCertificatesByID(req.Name, reason)
		if err != nil {
			return nil, newHTTPErr(500, ErrNoCertsRevoked, "Failed to revoke certificates for '%s': %s",
				req.Name, err)
		}

		if len(recs) == 0 {
			log.Warningf("No certificates were revoked for '%s' but the ID was disabled", req.Name)
		}

		log.Debugf("Revoked the following certificates owned by '%s': %+v", req.Name, recs)

	} else {
		return nil, newHTTPErr(400, ErrMissingRevokeArgs, "Either Name or Serial and AKI are required for a revoke request")
	}

	log.Debugf("Revoke was successful: %+v", req)

	// TODO: Return the AKI and serial number of certs which were revoked
	result := map[string]string{}
	return result, nil
}

func checkAffiliations(revoker string, revoking spi.UserInfo, ca *CA) error {
	log.Debugf("Check to see if revoker %s has affiliations to revoke: %s", revoker, revoking.Name)
	userAffiliation, err := ca.getUserAffiliation(revoker)
	if err != nil {
		return newHTTPErr(500, ErrGettingAffiliation, "Failed to get affiliation of %s: %s", revoker, err)
	}

	log.Debugf("Affiliation of revoker: %s, affiliation of identity being revoked: %s", userAffiliation, revoking.Affiliation)

	// Revoking user has root affiliation thus has ability to revoke
	if userAffiliation == "" {
		log.Debug("Identity with root affiliation revoking")
		return nil
	}

	revokingAffiliation := strings.Split(revoking.Affiliation, ".")
	revokerAffiliation := strings.Split(userAffiliation, ".")
	for i := range revokerAffiliation {
		if revokerAffiliation[i] != revokingAffiliation[i] {
			return newHTTPErr(401, ErrRevokerNotAffiliated,
				"Revoker %s does not have proper affiliation to revoke identity %s", revoker, revoking.Name)
		}
	}

	return nil
}
