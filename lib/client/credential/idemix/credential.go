/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/IBM/idemix/bccsp/types"
	schemes "github.com/IBM/idemix/bccsp/types"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

const (
	// CredType is the string that represents Idemix credential type
	CredType = "Idemix"
)

// Client represents a client that will load/store an Idemix credential
type Client interface {
	GetIssuerPubKey() (types.Key, error)
	GetCSP() bccsp.BCCSP
}

// Credential represents an Idemix credential. Implements Credential interface
type Credential struct {
	client           Client
	signerConfigFile string
	val              *SignerConfig
	csp              types.BCCSP
}

// NewCredential is constructor for idemix.Credential
func NewCredential(signerConfigFile string, c Client, csp types.BCCSP) *Credential {
	return &Credential{
		c, signerConfigFile, nil, csp,
	}
}

// Type returns Idemix
func (cred *Credential) Type() string {
	return CredType
}

// Val returns *SignerConfig associated with this Idemix credential
func (cred *Credential) Val() (interface{}, error) {
	if cred.val == nil {
		return nil, errors.New("Idemix credential value is not set")
	}
	return cred.val, nil
}

// EnrollmentID returns enrollment ID associated with this Idemix credential
func (cred *Credential) EnrollmentID() (string, error) {
	if cred.val == nil {
		return "", errors.New("Idemix credential value is not set")
	}
	return cred.val.EnrollmentID, nil
}

// RevocationHandle returns revocation handle associated with this Idemix credential
func (cred *Credential) RevocationHandle() (string, error) {
	if cred.val == nil {
		return "", errors.New("Idemix credential value is not set")
	}
	return cred.val.RevocationHandle, nil
}

// SetVal sets *SignerConfig for this Idemix credential
func (cred *Credential) SetVal(val interface{}) error {
	s, ok := val.(*SignerConfig)
	if !ok {
		return errors.New("The Idemix credential value must be of type *SignerConfig for idemix Credential")
	}
	cred.val = s
	return nil
}

// Store stores this Idemix credential to the location specified by the
// signerConfigFile attribute
func (cred *Credential) Store() error {
	val, err := cred.Val()
	if err != nil {
		return err
	}
	signerConfigBytes, err := json.Marshal(val)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal SignerConfig")
	}
	err = util.WriteFile(cred.signerConfigFile, signerConfigBytes, 0o644)
	if err != nil {
		return errors.WithMessage(err, "Failed to store the Idemix credential")
	}
	log.Infof("Stored the Idemix credential at %s", cred.signerConfigFile)
	return nil
}

// Load loads the Idemix credential from the location specified by the
// signerConfigFile attribute
func (cred *Credential) Load() error {
	signerConfigBytes, err := util.ReadFile(cred.signerConfigFile)
	if err != nil {
		log.Debugf("No credential found at %s: %s", cred.signerConfigFile, err.Error())
		return err
	}
	val := SignerConfig{}
	err = json.Unmarshal(signerConfigBytes, &val)
	if err != nil {
		return errors.Wrapf(err, fmt.Sprintf("Failed to unmarshal SignerConfig bytes from %s", cred.signerConfigFile))
	}

	cred.val = &val
	return nil
}

// CreateToken creates authorization token based on this Idemix credential
func (cred *Credential) CreateToken(req *http.Request, reqBody []byte) (string, error) {
	enrollmentID, err := cred.EnrollmentID()
	if err != nil {
		return "", err
	}
	// Get user's secret key

	sk, err := cred.csp.KeyImport(cred.val.GetSk(), &types.IdemixUserSecretKeyImportOpts{})
	if err != nil {
		return "", errors.WithMessage(err, "Failed to get user secret key")
	}

	// Get issuer public key
	ipk, err := cred.client.GetIssuerPubKey()
	if err != nil {
		return "", errors.WithMessage(err, "Failed to get CA's Idemix public key while creating token")
	}

	// Generate a fresh Pseudonym (and a corresponding randomness)

	NymKey, err := cred.csp.KeyDeriv(sk, &types.IdemixNymKeyDerivationOpts{Temporary: true, IssuerPK: ipk})
	if err != nil {
		return "", errors.WithMessage(err, "failed making Nym")
	}

	b64body := util.B64Encode(reqBody)
	b64uri := util.B64Encode([]byte(req.URL.RequestURI()))
	msg := req.Method + "." + b64uri + "." + b64body

	digest, digestError := cred.client.GetCSP().Hash([]byte(msg), &bccsp.SHAOpts{})
	if digestError != nil {
		return "", errors.WithMessage(digestError, fmt.Sprintf("Failed to create token '%s'", msg))
	}

	signOpts := &types.IdemixSignerOpts{
		Credential: cred.val.GetCred(),
		Nym:        NymKey,
		IssuerPK:   ipk,
		Attributes: []types.IdemixAttribute{
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
			{Type: types.IdemixHiddenAttribute},
		},
		RhIndex:  3,
		EidIndex: 2,
		Epoch:    0,
		SigType:  schemes.Standard,
		CRI:      cred.val.GetCredentialRevocationInformation(),
	}

	sig, err := cred.csp.Sign(
		sk,
		digest,
		signOpts,
	)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create signature while creating token")
	}

	token := "idemix." + api.IdemixTokenVersion1 + "." + enrollmentID + "." + util.B64Encode(sig)
	return token, nil
}

// RevokeSelf revokes this Idemix credential
func (cred *Credential) RevokeSelf() (*api.RevocationResponse, error) {
	return nil, errors.New("Not implemented") // TODO
}
