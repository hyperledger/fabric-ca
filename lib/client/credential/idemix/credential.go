/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"encoding/json"
	"fmt"
	"net/http"

	schemes "github.com/IBM/idemix/bccsp/schemes"
	scheme "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	math "github.com/IBM/mathlib"
	"github.com/cloudflare/cfssl/log"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/api"
	idemix4 "github.com/hyperledger/fabric-ca/lib/common/idemix"
	"github.com/hyperledger/fabric-ca/util"
	m "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

const (
	// CredType is the string that represents Idemix credential type
	CredType = "Idemix"
)

// Client represents a client that will load/store an Idemix credential
type Client interface {
	GetIssuerPubKey() (*scheme.IssuerPublicKey, error)
	GetCSP() bccsp.BCCSP
}

// Credential represents an Idemix credential. Implements Credential interface
type Credential struct {
	client           Client
	signerConfigFile string
	val              *SignerConfig
	curve            *math.Curve
	idemix           *scheme.Idemix
}

// NewCredential is constructor for idemix.Credential
func NewCredential(signerConfigFile string, c Client, id idemix4.CurveID) *Credential {
	return &Credential{
		c, signerConfigFile, nil, idemix4.CurveByID(id), idemix4.InstanceForCurve(id),
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
	caSignerConfig := val.(*SignerConfig)

	// Store the MSP signer config as Fabric expects
	mspSignerConfig := &m.IdemixMSPSignerConfig{
		Cred:                            caSignerConfig.Cred,
		Sk:                              caSignerConfig.Sk,
		OrganizationalUnitIdentifier:    caSignerConfig.OrganizationalUnitIdentifier,
		Role:                            int32(caSignerConfig.Role),
		EnrollmentId:                    caSignerConfig.EnrollmentID,
		CredentialRevocationInformation: caSignerConfig.CredentialRevocationInformation,
	}
	signerConfigBytes, err := proto.Marshal(mspSignerConfig)
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

	// Load the MSP signer config
	var val SignerConfig
	mspSignerConfig := &m.IdemixMSPSignerConfig{}
	err = proto.Unmarshal(signerConfigBytes, mspSignerConfig)
	if err == nil {
		val = SignerConfig{
			Cred:                            mspSignerConfig.Cred,
			Sk:                              mspSignerConfig.Sk,
			OrganizationalUnitIdentifier:    mspSignerConfig.OrganizationalUnitIdentifier,
			Role:                            int(mspSignerConfig.Role),
			EnrollmentID:                    mspSignerConfig.EnrollmentId,
			CredentialRevocationInformation: mspSignerConfig.CredentialRevocationInformation,
		}
	}

	if err != nil {
		// try to unmarshal via json
		val = SignerConfig{}
		err = json.Unmarshal(signerConfigBytes, &val)
		if err != nil {
			return errors.Wrapf(err, fmt.Sprintf("Failed to unmarshal SignerConfig bytes from %s", cred.signerConfigFile))
		}
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

	sk := cred.curve.NewZrFromBytes(cred.val.GetSk())

	// Get issuer public key
	ipk, err := cred.client.GetIssuerPubKey()
	if err != nil {
		return "", errors.WithMessage(err, "Failed to get CA's Idemix public key while creating token")
	}

	// Generate a fresh Pseudonym (and a corresponding randomness)

	rand, err := cred.curve.Rand()
	if err != nil {
		return "", errors.WithMessage(err, "Failed to get randomness source")
	}

	nym, randNym, err := cred.idemix.MakeNym(sk, ipk, rand, cred.idemix.Translator)
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

	// A disclosure vector is formed (indicating that only enrollment ID from the credential is revealed)
	disclosure := []byte{0, 0, 1, 0}

	credential := scheme.Credential{}
	err = proto.Unmarshal(cred.val.GetCred(), &credential)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to unmarshal Idemix credential while creating token")
	}
	cri := scheme.CredentialRevocationInformation{}
	err = proto.Unmarshal(cred.val.GetCredentialRevocationInformation(), &cri)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to unmarshal Idemix CRI while creating token")
	}

	sig, _, err := cred.idemix.NewSignature(&credential, sk, nym, randNym, ipk, disclosure, digest, 3, 0, &cri, rand, cred.idemix.Translator, schemes.Standard, nil)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create signature while creating token")
	}
	sigBytes, err := proto.Marshal(sig)
	if err != nil {
		return "", err
	}
	token := "idemix." + api.IdemixTokenVersion1 + "." + enrollmentID + "." + util.B64Encode(sigBytes)
	return token, nil
}

// RevokeSelf revokes this Idemix credential
func (cred *Credential) RevokeSelf() (*api.RevocationResponse, error) {
	return nil, errors.New("Not implemented") // TODO
}
