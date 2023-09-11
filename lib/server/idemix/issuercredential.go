/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"os"

	bccsp "github.com/IBM/idemix/bccsp/types"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
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
	// CA's Idemix secret key
	GetIssuerKey() (bccsp.Key, error)
	// SetIssuerKey sets issuer key
	SetIssuerKey(bccsp.Key)
	// Returns new instance of idemix.IssuerKey
	NewIssuerKey() (bccsp.Key, error)
}

// caIdemixCredential implements IssuerCredential interface
type caIdemixCredential struct {
	pubKeyFile    string
	secretKeyFile string
	issuerKey     bccsp.Key
	CSP           bccsp.BCCSP
}

// NewIssuerCredential returns an instance of an object that implements IssuerCredential interface
func NewIssuerCredential(pubKeyFile, secretKeyFile string, CSP bccsp.BCCSP) IssuerCredential {
	return &caIdemixCredential{
		pubKeyFile:    pubKeyFile,
		secretKeyFile: secretKeyFile,
		CSP:           CSP,
	}
}

// Load loads the CA's Idemix public and private key from the location specified
// by pubKeyFile and secretKeyFile attributes, respectively
func (ic *caIdemixCredential) Load() error {
	pubKeyBytes, err := os.ReadFile(ic.pubKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read Issuer public key")
	}
	if len(pubKeyBytes) == 0 {
		return errors.New("Issuer public key file is empty")
	}

	ic.issuerKey, err = ic.CSP.KeyImport(pubKeyBytes, &bccsp.IdemixIssuerPublicKeyImportOpts{Temporary: true, AttributeNames: GetAttributeNames()})
	if err != nil {
		return errors.Wrapf(err, "Failed to import Issuer key")
	}
	privKey, err := os.ReadFile(ic.secretKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read Issuer secret key")
	}
	if len(privKey) == 0 {
		return errors.New("Issuer secret key file is empty")
	}

	ic.issuerKey, err = ic.CSP.KeyImport(privKey, &bccsp.IdemixIssuerKeyImportOpts{Temporary: true, AttributeNames: GetAttributeNames()})
	if err != nil {
		return errors.Wrapf(err, "Failed to import Issuer key")
	}
	// TODO: check if issuer key is valid by checking public and secret key pair
	return nil
}

// Store stores the CA's Idemix public and private key to the location
// specified by pubKeyFile and secretKeyFile attributes, respectively
func (ic *caIdemixCredential) Store() error {
	isk, err := ic.GetIssuerKey()
	if err != nil {
		return err
	}

	ipk, err := isk.PublicKey()
	if err != nil {
		return errors.Wrapf(err, "Failed to obtain public key")
	}

	iskbytes, err := isk.Bytes()
	if err != nil {
		return errors.New("Failed to convert Issuer private key to bytes")
	}

	ipkbytes, err := ipk.Bytes()
	if err != nil {
		return errors.New("Failed to convert Issuer public key to bytes")
	}

	err = util.WriteFile(ic.pubKeyFile, ipkbytes, 0o644)
	if err != nil {
		log.Errorf("Failed to store Issuer public key: %s", err.Error())
		return errors.New("Failed to store Issuer public key")
	}

	err = util.WriteFile(ic.secretKeyFile, iskbytes, 0o644)
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
func (ic *caIdemixCredential) GetIssuerKey() (bccsp.Key, error) {
	if ic.issuerKey == nil {
		return nil, errors.New("Issuer credential is not set")
	}
	return ic.issuerKey, nil
}

// SetIssuerKey sets idemix.IssuerKey object
func (ic *caIdemixCredential) SetIssuerKey(key bccsp.Key) {
	ic.issuerKey = key
}

// NewIssuerKey creates new Issuer key
func (ic *caIdemixCredential) NewIssuerKey() (bccsp.Key, error) {
	// Currently, Idemix library supports these four attributes. The supported attribute names
	// must also be known when creating issuer key. In the future, Idemix library will support
	// arbitary attribute names, so removing the need to hardcode attribute names in the issuer
	// key.
	// OU - organization unit
	// Role - if the user is admin or member
	// EnrollmentID - enrollment ID of the user
	// RevocationHandle - revocation handle of a credential
	ik, err := ic.CSP.KeyGen(&bccsp.IdemixIssuerKeyGenOpts{Temporary: true, AttributeNames: GetAttributeNames()})
	if err != nil {
		return nil, err
	}
	return ik, nil
}

// GetAttributeNames returns attribute names supported by the Fabric CA for Idemix credentials
func GetAttributeNames() []string {
	return []string{AttrOU, AttrRole, AttrEnrollmentID, AttrRevocationHandle}
}
