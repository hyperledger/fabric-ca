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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/crl"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

const (
	crlPemType = "X509 CRL"
)

// The response to the POST /gencrl request
type genCRLResponseNet struct {
	// Base64 encoding of PEM-encoded CRL
	CRL string
}

func newGenCRLEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: genCRLHandler,
		Server:  s,
	}
}

// Handle an generate CRL request
func genCRLHandler(ctx *serverRequestContext) (interface{}, error) {
	var req api.GenCRLRequest
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	// Authenticate the invoker
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	log.Debugf("Received gencrl request from %s: %+v", id, util.StructToString(&req))

	// Get targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}

	// Make sure that the user has the "hf.GenCRL" attribute in order to be authorized
	// to generate CRL. This attribute comes from the user registry, which
	// is either in the DB if LDAP is not configured, or comes from LDAP if LDAP is
	// configured.
	err = ca.attributeIsTrue(id, "hf.GenCRL")
	if err != nil {
		return nil, newAuthErr(ErrNoGenCRLAuth, "The identity '%s' does not have authority to generate a CRL", id)
	}

	crl, err := genCRL(ca, req)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully generated CRL")

	resp := &genCRLResponseNet{CRL: util.B64Encode(crl)}
	return resp, nil
}

// GenCRL will generate CRL
func genCRL(ca *CA, req api.GenCRLRequest) ([]byte, error) {
	var err error
	if !req.RevokedBefore.IsZero() && req.RevokedAfter.After(req.RevokedBefore) {
		return nil, newHTTPErr(400, ErrInvalidRevokedAfter,
			"Invalid 'revokedafter' value. It must not be a timestamp greater than 'revokedbefore'")
	}

	if !req.ExpireBefore.IsZero() && req.ExpireAfter.After(req.ExpireBefore) {
		return nil, newHTTPErr(400, ErrInvalidExpiredAfter,
			"Invalid 'expireafter' value. It must not be a timestamp greater than 'expirebefore'")
	}

	// Get revoked certificates from the database
	certs, err := ca.certDBAccessor.GetRevokedCertificates(req.ExpireAfter, req.ExpireBefore, req.RevokedAfter, req.RevokedBefore)
	if err != nil {
		log.Errorf("Failed to get revoked certificates from the database: %s", err)
		return nil, newHTTPErr(500, ErrRevokedCertsFromDB, "Failed to get revoked certificates")
	}

	caCert, err := getCACert(ca)
	if err != nil {
		log.Errorf("Failed to get certficate for CA '%s': %s", ca.HomeDir, err)
		return nil, newHTTPErr(500, ErrGetCACert, "Failed to get certficate for CA '%s'", ca.HomeDir)
	}

	if !canSignCRL(caCert) {
		return nil, newHTTPErr(500, ErrNoCrlSignAuth,
			"The CA does not have authority to generate a CRL. Its certificate does not have 'crl sign' key usage")
	}

	// Get the signer for the CA
	_, signer, err := util.GetSignerFromCert(caCert, ca.csp)
	if err != nil {
		log.Errorf("Failed to get signer for CA '%s': %s", ca.HomeDir, err)
		return nil, newHTTPErr(500, ErrGetCASigner, "Failed to get signer for CA '%s'", ca.HomeDir)
	}

	expiry := time.Now().UTC().Add(ca.Config.CRL.Expiry)
	var revokedCerts []pkix.RevokedCertificate

	// For every record, create a new revokedCertificate and add it to slice
	for _, certRecord := range certs {
		serialInt := new(big.Int)
		serialInt.SetString(certRecord.Serial, 16)
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   serialInt,
			RevocationTime: certRecord.RevokedAt,
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}

	crl, err := crl.CreateGenericCRL(revokedCerts, signer, caCert, expiry)
	if err != nil {
		log.Errorf("Failed to generate CRL for CA '%s': %s", ca.HomeDir, err)
		return nil, newHTTPErr(500, ErrGenCRL, "Failed to generate CRL for CA '%s'", ca.HomeDir)
	}
	blk := &pem.Block{Bytes: crl, Type: crlPemType}
	return pem.EncodeToMemory(blk), nil
}

func getCACert(ca *CA) (*x509.Certificate, error) {
	// Get CA certificate
	caCertBytes, err := ioutil.ReadFile(ca.Config.CA.Certfile)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to read certificate for the CA '%s'", ca.HomeDir))
	}
	caCert, err := BytesToX509Cert(caCertBytes)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get certificate for the CA '%s'", ca.HomeDir))
	}
	return caCert, nil
}
