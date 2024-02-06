/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	bccsp "github.com/IBM/idemix/bccsp/types"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// EnrollmentResponse is the idemix enrollment response from the server
type EnrollmentResponse struct {
	// Base64 encoding of idemix Credential
	Credential string
	// Attribute name-value pairs
	Attrs map[string]interface{}
	// Base64 encoding of Credential Revocation information
	CRI string
	// Base64 encoding of the issuer nonce
	Nonce string
}

//go:generate mockery --name BccspBCCSP --case underscore
type BccspBCCSP interface {
	bccsp.BCCSP
}

//go:generate mockery --name BccspKey --case underscore
type BccspKey interface {
	bccsp.Key
}

// EnrollRequestHandler is the handler for Idemix enroll request
type EnrollRequestHandler struct {
	Ctx          ServerRequestCtx
	EnrollmentID string
	Issuer       *IssuerInst
	CSP          bccsp.BCCSP
}

// HandleRequest handles processing for Idemix enroll
func (h *EnrollRequestHandler) HandleRequest() (*EnrollmentResponse, error) {
	err := h.Authenticate()
	if err != nil {
		return nil, err
	}

	var req api.IdemixEnrollmentRequestNet
	err = h.Ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	if req.CredRequest == nil {
		nonce, err := h.Issuer.NonceManager.GetNonce()
		if err != nil {
			return nil, errors.New("Failed to generate nonce")
		}

		resp := &EnrollmentResponse{
			Nonce: util.B64Encode(nonce),
		}
		return resp, nil
	}

	isk, err := h.Issuer.IssuerCred.GetIssuerKey()
	if err != nil {
		log.Errorf("Failed to get Idemix issuer key for the CA %s: %s", h.Issuer.Name, err.Error())
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get Idemix issuer key for the CA: %s",
			h.Issuer.Name))
	}

	ipk, err := isk.PublicKey()
	if err != nil {
		log.Errorf("Failed to get Idemix public issuer key for the CA %s: %s", h.Issuer.Name, err.Error())
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get Idemix public issuer key for the CA: %s",
			h.Issuer.Name))
	}

	caller, err := h.Ctx.GetCaller()
	if err != nil {
		log.Errorf("Failed to get caller of the request: %s", err.Error())
		return nil, err
	}

	err = h.Issuer.NonceManager.CheckNonce(req.IssuerNonce)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid nonce")
	}

	valid, err := h.CSP.Verify(ipk, req.CredRequest, nil, &bccsp.IdemixCredentialRequestSignerOpts{IssuerNonce: req.IssuerNonce})
	if err != nil || !valid {
		log.Errorf("Invalid Idemix credential request: %s", err.Error())
		return nil, errors.WithMessage(err, "Invalid Idemix credential request")
	}

	// Get revocation handle for the credential
	rh, err := h.Issuer.RevocationAuthority.GetNewRevocationHandle()
	if err != nil {
		return nil, err
	}

	// convert the revocation handle rh to a string by first converting it to int64.
	rhStr := fmt.Sprintf("%d", rh)

	// Get attributes for the identity
	attrs, attrMap, err := h.GetAttributeValues(caller, GetAttributeNames(), rh)
	if err != nil {
		return nil, err
	}

	credential, err := h.CSP.Sign(
		isk,
		req.CredRequest,
		&bccsp.IdemixCredentialSignerOpts{
			Attributes: attrs,
		},
	)
	if err != nil {
		log.Errorf("Issuer '%s' failed to create new Idemix credential for identity '%s': %s",
			h.Issuer.Name, h.EnrollmentID, err.Error())
		return nil, errors.New("Failed to create new Idemix credential")
	}

	b64CredBytes := util.B64Encode(credential)

	// Store the credential in the database
	err = h.Issuer.CredDBAccessor.InsertCredential(CredRecord{
		CALabel:          h.Issuer.Name,
		ID:               caller.GetName(),
		Status:           "good",
		Cred:             b64CredBytes,
		RevocationHandle: rhStr,
	})
	if err != nil {
		log.Errorf("Failed to store the Idemix credential for identity '%s' in the database: %s", caller.GetName(), err.Error())
		return nil, errors.New("Failed to store the Idemix credential")
	}

	// Get CRL from revocation authority of the CA
	cri, err := h.Issuer.RevocationAuthority.CreateCRI()
	if err != nil {
		log.Errorf("Failed to generate CRI while processing idemix/credential request: %s", err.Error())
		return nil, errors.New("Failed to generate CRI")
	}

	b64CriBytes := util.B64Encode(cri)
	resp := &EnrollmentResponse{
		Credential: b64CredBytes,
		Attrs:      attrMap,
		CRI:        b64CriBytes,
	}

	if h.Ctx.IsBasicAuth() {
		err = caller.LoginComplete()
		if err != nil {
			return nil, err
		}
	}

	// Success
	return resp, nil
}

// Authenticate authenticates the Idemix enroll request
func (h *EnrollRequestHandler) Authenticate() error {
	var err error
	if h.Ctx.IsBasicAuth() {
		h.EnrollmentID, err = h.Ctx.BasicAuthentication()
		if err != nil {
			return err
		}
	} else {
		h.EnrollmentID, err = h.Ctx.TokenAuthentication()
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateNonce generates a nonce for an Idemix enroll request
func (h *EnrollRequestHandler) GenerateNonce() ([]byte, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)

	return nonceBytes, err
}

// GetAttributeValues returns attribute values of the caller of Idemix enroll request
func (h *EnrollRequestHandler) GetAttributeValues(caller user.User, attributes []string,
	rh int64) ([]bccsp.IdemixAttribute, map[string]interface{}, error) {
	attrMap := make(map[string]interface{})
	attrs := make([]bccsp.IdemixAttribute, len(attributes))
	for i, attrName := range attributes {
		if attrName == AttrEnrollmentID {
			attrs[i].Type = bccsp.IdemixBytesAttribute
			attrs[i].Value = []byte(caller.GetName())
			attrMap[attrName] = caller.GetName()
		} else if attrName == AttrOU {
			ou := append([]string{}, caller.GetAffiliationPath()...)
			ouVal := strings.Join(ou, ".")
			attrs[i].Value = []byte(ouVal)
			attrs[i].Type = bccsp.IdemixBytesAttribute
			attrMap[attrName] = ouVal
		} else if attrName == AttrRevocationHandle {
			rhStr := fmt.Sprintf("%d", rh)
			attrs[i].Value = []byte(rhStr)
			attrs[i].Type = bccsp.IdemixBytesAttribute
			attrMap[attrName] = rhStr
		} else if attrName == AttrRole {
			role := MEMBER.getValue()
			attrObj, err := caller.GetAttribute("role")
			if err == nil {
				role, err = strconv.Atoi(attrObj.GetValue())
				if err != nil {
					log.Debugf("role attribute of user %s must be a integer value", caller.GetName())
				}
			}
			attrs[i].Value = role
			attrs[i].Type = bccsp.IdemixIntAttribute
			attrMap[attrName] = role
		} else {
			log.Errorf("unknown attribute %s for user %s", attrName, caller.GetName())
		}
	}

	return attrs, attrMap, nil
}
