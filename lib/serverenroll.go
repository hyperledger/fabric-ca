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
	"encoding/asn1"
	"encoding/pem"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	commonNameLength             = 64
	serialNumberLength           = 64
	countryNameLength            = 2
	localityNameLength           = 128
	stateOrProvinceNameLength    = 128
	organizationNameLength       = 64
	organizationalUnitNameLength = 64
)

var (
	// The X.509 BasicConstraints object identifier (RFC 5280, 4.2.1.9)
	basicConstraintsOID   = asn1.ObjectIdentifier{2, 5, 29, 19}
	commonNameOID         = asn1.ObjectIdentifier{2, 5, 4, 3}
	serialNumberOID       = asn1.ObjectIdentifier{2, 5, 4, 5}
	countryOID            = asn1.ObjectIdentifier{2, 5, 4, 6}
	localityOID           = asn1.ObjectIdentifier{2, 5, 4, 7}
	stateOID              = asn1.ObjectIdentifier{2, 5, 4, 8}
	organizationOID       = asn1.ObjectIdentifier{2, 5, 4, 10}
	organizationalUnitOID = asn1.ObjectIdentifier{2, 5, 4, 11}
)

// The enrollment response from the server
type enrollmentResponseNet struct {
	// Base64 encoded PEM-encoded ECert
	Cert string
	// The server information
	ServerInfo serverInfoResponseNet
}

func newEnrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: enrollHandler,
		Server:  s,
	}
}

func newReenrollEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods: []string{"POST"},
		Handler: reenrollHandler,
		Server:  s,
	}
}

// Handle an enroll request, guarded by basic authentication
func enrollHandler(ctx *serverRequestContext) (interface{}, error) {
	id, err := ctx.BasicAuthentication()
	if err != nil {
		return nil, err
	}
	return handleEnroll(ctx, id)
}

// Handle a reenroll request, guarded by token authentication
func reenrollHandler(ctx *serverRequestContext) (interface{}, error) {
	// Authenticate the caller
	id, err := ctx.TokenAuthentication()
	if err != nil {
		return nil, err
	}
	return handleEnroll(ctx, id)
}

// Handle the common processing for enroll and reenroll
func handleEnroll(ctx *serverRequestContext, id string) (interface{}, error) {
	var req api.EnrollmentRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	// Get the targeted CA
	ca, err := ctx.GetCA()
	if err != nil {
		return nil, err
	}
	// Authorization the caller, depending on the contents of the
	// CSR (Certificate Signing Request)
	err = csrAuthCheck(id, &req.SignRequest, ca)
	if err != nil {
		return nil, err
	}
	// Get an attribute extension if one is being requested
	ext, err := ctx.GetAttrExtension(req.AttrReqs, req.Profile)
	if err != nil {
		return nil, err
	}
	// If there is an extension requested, add it to the request
	if ext != nil {
		log.Debugf("Adding attribute extension to CSR: %+v", ext)
		req.Extensions = append(req.Extensions, *ext)
	}
	// Sign the certificate
	cert, err := ca.enrollSigner.Sign(req.SignRequest)
	if err != nil {
		return nil, errors.WithMessage(err, "Certificate signing failure")
	}
	// Add server info to the response
	resp := &enrollmentResponseNet{
		Cert: util.B64Encode(cert),
	}
	err = ca.fillCAInfo(&resp.ServerInfo)
	if err != nil {
		return nil, err
	}
	// Success
	return resp, nil
}

// Make any authorization checks needed, depending on the contents
// of the CSR (Certificate Signing Request).
// In particular, if the request is for an intermediate CA certificate,
// the caller must have the "hf.IntermediateCA" attribute.
// Also check to see that CSR values do not exceed the character limit
// as specified in RFC 3280, page 103.
func csrAuthCheck(id string, req *signer.SignRequest, ca *CA) error {
	// Decode and parse the request into a CSR so we can make checks
	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a certificate or csr"))
	}
	csrReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	log.Debugf("csrAuthCheck: id=%s, CommonName=%s, Subject=%+v", id, csrReq.Subject.CommonName, req.Subject)
	if (req.Subject != nil && req.Subject.CN != id) || csrReq.Subject.CommonName != id {
		return errors.New("The CSR subject common name must equal the enrollment ID")
	}
	// Check the CSR for the X.509 BasicConstraints extension (RFC 5280, 4.2.1.9)
	for _, val := range csrReq.Extensions {
		if val.Id.Equal(basicConstraintsOID) {
			var constraints csr.BasicConstraints
			var rest []byte
			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				return newHTTPErr(400, ErrBadCSR, "Failed parsing CSR constraints: %s", err)
			} else if len(rest) != 0 {
				return newHTTPErr(400, ErrBadCSR, "Trailing data after X.509 BasicConstraints")
			}
			if constraints.IsCA {
				log.Debug("CSR request received for an intermediate CA")
				// This is a request for a CA certificate, so make sure the caller
				// has the 'hf.IntermediateCA' attribute
				return ca.attributeIsTrue(id, "hf.IntermediateCA")
			}
		}
	}
	log.Debug("CSR authorization check passed")
	return csrInputLengthCheck(csrReq)
}

// Checks to make sure that character limits are not exceeded for CSR fields
func csrInputLengthCheck(req *x509.CertificateRequest) error {
	log.Debug("Checking CSR fields to make sure that they do not exceed maximum character limits")

	for _, n := range req.Subject.Names {
		value := n.Value.(string)
		switch {
		case n.Type.Equal(commonNameOID):
			if len(value) > commonNameLength {
				return errors.Errorf("The CN '%s' exceeds the maximum character limit of %d", value, commonNameLength)
			}
		case n.Type.Equal(serialNumberOID):
			if len(value) > serialNumberLength {
				return errors.Errorf("The serial number '%s' exceeds the maximum character limit of %d", value, serialNumberLength)
			}
		case n.Type.Equal(organizationalUnitOID):
			if len(value) > organizationalUnitNameLength {
				return errors.Errorf("The organizational unit name '%s' exceeds the maximum character limit of %d", value, organizationalUnitNameLength)
			}
		case n.Type.Equal(organizationOID):
			if len(value) > organizationNameLength {
				return errors.Errorf("The organization name '%s' exceeds the maximum character limit of %d", value, organizationNameLength)
			}
		case n.Type.Equal(countryOID):
			if len(value) > countryNameLength {
				return errors.Errorf("The country name '%s' exceeds the maximum character limit of %d", value, countryNameLength)
			}
		case n.Type.Equal(localityOID):
			if len(value) > localityNameLength {
				return errors.Errorf("The locality name '%s' exceeds the maximum character limit of %d", value, localityNameLength)
			}
		case n.Type.Equal(stateOID):
			if len(value) > stateOrProvinceNameLength {
				return errors.Errorf("The state name '%s' exceeds the maximum character limit of %d", value, stateOrProvinceNameLength)
			}
		}
	}

	return nil
}
