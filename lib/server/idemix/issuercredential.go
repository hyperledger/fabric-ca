/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"io/ioutil"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

const (
	// AttrEnrollmentID is the attribute name for enrollment ID
	AttrEnrollmentID = "EnrollmentID"
	// AttrRole is the attribute name for role
	AttrRole = "Role"
	// AttrOU is the attribute name for OU
	AttrOU = "OU"
	// AttrRevocationHandle is the attribute name for revocation handle
	AttrRevocationHandle = "RevocationHandle"
)

// IssuerCredential represents CA's Idemix credential
type IssuerCredential interface {
	// Load loads the CA's Idemix credential from the disk
	Load() error
	// Store stores the CA's Idemix credential to the disk
	Store() error
	// GetIssuerKey returns *idemix.IssuerKey that represents
	// CA's Idemix public and secret key
	GetIssuerKey() (*idemix.IssuerKey, error)
	// SetIssuerKey sets issuer key
	SetIssuerKey(key *idemix.IssuerKey)
	// Returns new instance of idemix.IssuerKey
	NewIssuerKey() (*idemix.IssuerKey, error)
}

// caIdemixCredential implements IssuerCredential interface
type caIdemixCredential struct {
	pubKeyFile    string
	secretKeyFile string
	issuerKey     *idemix.IssuerKey
	idemixLib     Lib
}

// NewIssuerCredential returns an instance of an object that implements IssuerCredential interface
func NewIssuerCredential(pubKeyFile, secretKeyFile string, lib Lib) IssuerCredential {
	return &caIdemixCredential{
		pubKeyFile:    pubKeyFile,
		secretKeyFile: secretKeyFile,
		idemixLib:     lib,
	}
}

// Load loads the CA's Idemix public and private key from the location specified
// by pubKeyFile and secretKeyFile attributes, respectively
func (ic *caIdemixCredential) Load() error {
	pubKeyBytes, err := ioutil.ReadFile(ic.pubKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read Issuer public key")
	}
	if len(pubKeyBytes) == 0 {
		return errors.New("Issuer public key file is empty")
	}
	pubKey := &idemix.IssuerPublicKey{}
	err = proto.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		return errors.Wrapf(err, "Failed to unmarshal Issuer public key bytes")
	}
	err = pubKey.Check()
	if err != nil {
		return errors.Wrapf(err, "Issuer public key check failed")
	}
	privKey, err := ioutil.ReadFile(ic.secretKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read Issuer secret key")
	}
	if len(privKey) == 0 {
		return errors.New("Issuer secret key file is empty")
	}
	ic.issuerKey = &idemix.IssuerKey{
		Ipk: pubKey,
		Isk: privKey,
	}
	//TODO: check if issuer key is valid by checking public and secret key pair
	return nil
}

// Store stores the CA's Idemix public and private key to the location
// specified by pubKeyFile and secretKeyFile attributes, respectively
func (ic *caIdemixCredential) Store() error {
	ik, err := ic.GetIssuerKey()
	if err != nil {
		return err
	}

	ipkBytes, err := proto.Marshal(ik.Ipk)
	if err != nil {
		return errors.New("Failed to marshal Issuer public key")
	}

	err = util.WriteFile(ic.pubKeyFile, ipkBytes, 0644)
	if err != nil {
		log.Errorf("Failed to store Issuer public key: %s", err.Error())
		return errors.New("Failed to store Issuer public key")
	}

	err = util.WriteFile(ic.secretKeyFile, ik.Isk, 0644)
	if err != nil {
		log.Errorf("Failed to store Issuer secret key: %s", err.Error())
		return errors.New("Failed to store Issuer secret key")
	}

	log.Infof("The issuer key was successfully stored. The public key is at: %s, secret key is at: %s",
		ic.pubKeyFile, ic.secretKeyFile)
	return nil
}

// GetIssuerKey returns idemix.IssuerKey object that is associated with
// this CAIdemixCredential
func (ic *caIdemixCredential) GetIssuerKey() (*idemix.IssuerKey, error) {
	if ic.issuerKey == nil {
		return nil, errors.New("Issuer credential is not set")
	}
	return ic.issuerKey, nil
}

// SetIssuerKey sets idemix.IssuerKey object
func (ic *caIdemixCredential) SetIssuerKey(key *idemix.IssuerKey) {
	ic.issuerKey = key
}

// NewIssuerKey creates new Issuer key
func (ic *caIdemixCredential) NewIssuerKey() (*idemix.IssuerKey, error) {
	rng, err := ic.idemixLib.GetRand()
	if err != nil {
		return nil, errors.Wrapf(err, "Error creating new issuer key")
	}
	// Currently, Idemix library supports these four attributes. The supported attribute names
	// must also be known when creating issuer key. In the future, Idemix library will support
	// arbitary attribute names, so removing the need to hardcode attribute names in the issuer
	// key.
	// OU - organization unit
	// Role - if the user is admin or member
	// EnrollmentID - enrollment ID of the user
	// RevocationHandle - revocation handle of a credential
	ik, err := ic.idemixLib.NewIssuerKey(GetAttributeNames(), rng)
	if err != nil {
		return nil, err
	}
	return ik, nil
}

// GetAttributeNames returns attribute names supported by the Fabric CA for Idemix credentials
func GetAttributeNames() []string {
	return []string{AttrOU, AttrRole, AttrEnrollmentID, AttrRevocationHandle}
}
