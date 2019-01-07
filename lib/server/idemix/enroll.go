/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
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

// EnrollRequestHandler is the handler for Idemix enroll request
type EnrollRequestHandler struct {
	Ctx          ServerRequestCtx
	EnrollmentID string
	Issuer       MyIssuer
	IdmxLib      Lib
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
		nonce, err := h.Issuer.NonceManager().GetNonce()
		if err != nil {
			return nil, errors.New("Failed to generate nonce")
		}

		resp := &EnrollmentResponse{
			Nonce: util.B64Encode(idemix.BigToBytes(nonce)),
		}
		return resp, nil
	}

	ik, err := h.Issuer.IssuerCredential().GetIssuerKey()
	if err != nil {
		log.Errorf("Failed to get Idemix issuer key for the CA %s: %s", h.Issuer.Name(), err.Error())
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get Idemix issuer key for the CA: %s",
			h.Issuer.Name()))
	}

	caller, err := h.Ctx.GetCaller()
	if err != nil {
		log.Errorf("Failed to get caller of the request: %s", err.Error())
		return nil, err
	}

	nonce := fp256bn.FromBytes(req.GetIssuerNonce())
	err = h.Issuer.NonceManager().CheckNonce(nonce)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid nonce")
	}

	// Check the if credential request is valid
	err = req.CredRequest.Check(ik.GetIpk())
	if err != nil {
		log.Errorf("Invalid Idemix credential request: %s", err.Error())
		return nil, errors.WithMessage(err, "Invalid Idemix credential request")
	}

	// Get revocation handle for the credential
	rh, err := h.Issuer.RevocationAuthority().GetNewRevocationHandle()
	if err != nil {
		return nil, err
	}

	// Get attributes for the identity
	attrMap, attrs, err := h.GetAttributeValues(caller, ik.GetIpk(), rh)
	if err != nil {
		return nil, err
	}

	cred, err := h.IdmxLib.NewCredential(ik, req.CredRequest, attrs, h.Issuer.IdemixRand())
	if err != nil {
		log.Errorf("Issuer '%s' failed to create new Idemix credential for identity '%s': %s",
			h.Issuer.Name(), h.EnrollmentID, err.Error())
		return nil, errors.New("Failed to create new Idemix credential")
	}
	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return nil, errors.New("Failed to marshal Idemix credential to bytes")
	}
	b64CredBytes := util.B64Encode(credBytes)

	rhstr := util.B64Encode(idemix.BigToBytes(rh))

	// Store the credential in the database
	err = h.Issuer.CredDBAccessor().InsertCredential(CredRecord{
		CALabel:          h.Issuer.Name(),
		ID:               caller.GetName(),
		Status:           "good",
		Cred:             b64CredBytes,
		RevocationHandle: rhstr,
	})
	if err != nil {
		log.Errorf("Failed to store the Idemix credential for identity '%s' in the database: %s", caller.GetName(), err.Error())
		return nil, errors.New("Failed to store the Idemix credential")
	}

	// Get CRL from revocation authority of the CA
	cri, err := h.Issuer.RevocationAuthority().CreateCRI()
	if err != nil {
		log.Errorf("Failed to generate CRI while processing idemix/credential request: %s", err.Error())
		return nil, errors.New("Failed to generate CRI")
	}
	criBytes, err := proto.Marshal(cri)
	if err != nil {
		return nil, errors.New("Failed to marshal CRI to bytes")
	}
	b64CriBytes := util.B64Encode(criBytes)
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
func (h *EnrollRequestHandler) GenerateNonce() (*fp256bn.BIG, error) {
	return h.IdmxLib.RandModOrder(h.Issuer.IdemixRand())
}

// GetAttributeValues returns attribute values of the caller of Idemix enroll request
func (h *EnrollRequestHandler) GetAttributeValues(caller user.User, ipk *idemix.IssuerPublicKey,
	rh *fp256bn.BIG) (map[string]interface{}, []*fp256bn.BIG, error) {
	rc := []*fp256bn.BIG{}
	attrMap := make(map[string]interface{})
	for _, attrName := range ipk.AttributeNames {
		if attrName == AttrEnrollmentID {
			idBytes := []byte(caller.GetName())
			rc = append(rc, idemix.HashModOrder(idBytes))
			attrMap[attrName] = caller.GetName()
		} else if attrName == AttrOU {
			ou := []string{}
			for _, aff := range caller.GetAffiliationPath() {
				ou = append(ou, aff)
			}
			ouVal := strings.Join(ou, ".")
			ouBytes := []byte(ouVal)
			rc = append(rc, idemix.HashModOrder(ouBytes))
			attrMap[attrName] = ouVal
		} else if attrName == AttrRevocationHandle {
			rc = append(rc, rh)
			attrMap[attrName] = util.B64Encode(idemix.BigToBytes(rh))
		} else if attrName == AttrRole {
			role := MEMBER.getValue()
			attrObj, err := caller.GetAttribute("role")
			if err == nil {
				role, err = strconv.Atoi(attrObj.GetValue())
				if err != nil {
					log.Debugf("role attribute of user %s must be a integer value", caller.GetName())
				}
			}
			rc = append(rc, fp256bn.NewBIGint(role))
			attrMap[attrName] = role
		} else {
			attrObj, err := caller.GetAttribute(attrName)
			if err != nil {
				log.Errorf("Failed to get attribute %s for user %s: %s", attrName, caller.GetName(), err.Error())
			} else {
				attrBytes := []byte(attrObj.GetValue())
				rc = append(rc, idemix.HashModOrder(attrBytes))
				attrMap[attrName] = attrObj.GetValue()
			}
		}
	}
	return attrMap, rc, nil
}
