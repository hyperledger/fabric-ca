/*
Copyright IBM Corp. 2018 All Rights Reserved.

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

package idemix

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	amcl "github.com/hyperledger/fabric-amcl/amcl"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

// ServerRequestCtx is the server request context that Idemix enroll expects
type ServerRequestCtx interface {
	BasicAuthentication() (string, error)
	TokenAuthentication() (string, error)
	GetCA() (CA, error)
	GetCaller() (spi.User, error)
	ReadBody(body interface{}) error
}

// CA is the CA that Idemix enroll expects
type CA interface {
	GetName() string
	DB() dbutil.FabricCADB
	IdemixRand() *amcl.RAND
	IssuerCredential() IssuerCredential
	RevocationComponent() RevocationComponent
	NonceManager() NonceManager
	CredDBAccessor() CredDBAccessor
}

// EnrollmentResponse is the idemix enrollment response from the server
type EnrollmentResponse struct {
	// Base64 encoding of idemix Credential
	Credential string
	// Attribute name-value pairs
	Attrs map[string]string
	// Base64 encoding of Credential Revocation list
	//CRL string
	// Base64 encoding of the issuer nonce
	Nonce string
}

// EnrollRequestHandler is the handler for Idemix enroll request
type EnrollRequestHandler struct {
	IsBasicAuth  bool
	Ctx          ServerRequestCtx
	EnrollmentID string
	CA           CA
	IdmxLib      Lib
}

// HandleIdemixEnroll handles processing for Idemix enroll
func (h *EnrollRequestHandler) HandleIdemixEnroll() (*EnrollmentResponse, error) {
	err := h.Authenticate()
	if err != nil {
		return nil, err
	}

	var req api.IdemixEnrollmentRequestNet
	err = h.Ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	// Get the targeted CA
	h.CA, err = h.Ctx.GetCA()
	if err != nil {
		return nil, err
	}

	if req.CredRequest == nil {
		nonce, err := h.CA.NonceManager().GetNonce()
		if err != nil {
			return nil, errors.New("Failed to generate nonce")
		}

		resp := &EnrollmentResponse{
			Nonce: util.B64Encode(idemix.BigToBytes(nonce)),
		}
		return resp, nil
	}

	ik, err := h.CA.IssuerCredential().GetIssuerKey()
	if err != nil {
		log.Errorf("Failed to get Idemix issuer key for the CA %s: %s", h.CA.GetName(), err.Error())
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to get Idemix issuer key for the CA: %s",
			h.CA.GetName()))
	}

	caller, err := h.Ctx.GetCaller()
	if err != nil {
		log.Errorf("Failed to get caller of the request: %s", err.Error())
		return nil, err
	}

	nonce := fp256bn.FromBytes(req.GetIssuerNonce())
	err = h.CA.NonceManager().CheckNonce(nonce)
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid nonce")
	}

	// Check the if credential request is valid
	err = req.CredRequest.Check(ik.GetIPk())
	if err != nil {
		log.Errorf("Invalid Idemix credential request: %s", err.Error())
		return nil, errors.WithMessage(err, "Invalid Idemix credential request")
	}

	// Get revocation handle for the credential
	rh, err := h.CA.RevocationComponent().GetNewRevocationHandle()
	if err != nil {
		return nil, err
	}

	// Get attributes for the identity
	attrMap, attrs, err := h.GetAttributeValues(caller, ik.GetIPk(), rh)
	if err != nil {
		return nil, err
	}

	cred, err := h.IdmxLib.NewCredential(ik, req.CredRequest, attrs, h.CA.IdemixRand())
	if err != nil {
		log.Errorf("CA '%s' failed to create new Idemix credential for identity '%s': %s",
			h.CA.GetName(), h.EnrollmentID, err.Error())
		return nil, errors.New("Failed to create new Idemix credential")
	}
	credBytes, err := proto.Marshal(cred)
	if err != nil {
		return nil, errors.New("Failed to marshal Idemix credential to bytes")
	}
	b64CredBytes := util.B64Encode(credBytes)

	// Store the credential in the database
	err = h.CA.CredDBAccessor().InsertCredential(CredRecord{
		CALabel:          h.CA.GetName(),
		ID:               caller.GetName(),
		Status:           "good",
		Cred:             b64CredBytes,
		RevocationHandle: int(*rh),
	})
	if err != nil {
		log.Errorf("Failed to store the Idemix credential for identity '%s' in the database: %s", caller.GetName(), err.Error())
		return nil, errors.New("Failed to store the Idemix credential")
	}

	// TODO: Get CRL from revocation authority of the CA

	resp := &EnrollmentResponse{
		Credential: b64CredBytes,
		Attrs:      attrMap,
	}

	if h.IsBasicAuth {
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
	if h.IsBasicAuth {
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
func (h *EnrollRequestHandler) GenerateNonce() *fp256bn.BIG {
	return h.IdmxLib.RandModOrder(h.CA.IdemixRand())
}

// GetAttributeValues returns attribute values of the caller of Idemix enroll request
func (h *EnrollRequestHandler) GetAttributeValues(caller spi.User, ipk *idemix.IssuerPublicKey,
	rh *RevocationHandle) (map[string]string, []*fp256bn.BIG, error) {
	rc := []*fp256bn.BIG{}
	attrMap := make(map[string]string)
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
			rhi := int(*rh)
			rc = append(rc, fp256bn.NewBIGint(rhi))
			attrMap[attrName] = strconv.Itoa(rhi)
		} else if attrName == AttrRole {
			isAdmin := false
			attrObj, err := caller.GetAttribute("isAdmin")
			if err == nil {
				isAdmin, err = strconv.ParseBool(attrObj.GetValue())
			}
			role := 0
			if isAdmin {
				role = 1
			}
			rc = append(rc, fp256bn.NewBIGint(int(role)))
			attrMap[attrName] = strconv.FormatBool(isAdmin)
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
