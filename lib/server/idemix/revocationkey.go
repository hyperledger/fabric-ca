/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"encoding/pem"
	"os"

	"github.com/IBM/idemix/bccsp/types"
	bccsp "github.com/IBM/idemix/bccsp/types"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// RevocationKey represents issuer revocation public and private key
type RevocationKey interface {
	// Load loads this revocation key from the disk
	Load() error
	// Store stores this revocation key to the disk
	Store() error
	// GetKey returns bccsp.Key that represents revocation public and private key pair
	GetKey() bccsp.Key
	// SetKey sets revocation public and private key
	SetKey(key bccsp.Key)
	// SetNewKey creates new revocation public and private key pair and sets them in this object
	SetNewKey() error
}

// caIdemixRevocationKey implements RevocationKey interface
type caIdemixRevocationKey struct {
	pubKeyFile     string
	privateKeyFile string
	key            bccsp.Key
	CSP            bccsp.BCCSP
}

// NewRevocationKey returns an instance of an object that implements RevocationKey interface
func NewRevocationKey(pubKeyFile, privateKeyFile string, CSP bccsp.BCCSP) RevocationKey {
	return &caIdemixRevocationKey{
		pubKeyFile:     pubKeyFile,
		privateKeyFile: privateKeyFile,
		CSP:            CSP,
	}
}

// Load loads the Issuer revocation public and private key from the location specified
// by pubKeyFile and privateKeyFile attributes, respectively
func (rk *caIdemixRevocationKey) Load() error {
	pubKeyBytes, err := os.ReadFile(rk.pubKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read revocation public key from %s", rk.pubKeyFile)
	}
	if len(pubKeyBytes) == 0 {
		return errors.New("Revocation public key file is empty")
	}
	privKeyBytes, err := os.ReadFile(rk.privateKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read revocation private key from %s", rk.privateKeyFile)
	}
	if len(privKeyBytes) == 0 {
		return errors.New("Revocation private key file is empty")
	}

	revPrivKey, err := rk.CSP.KeyImport(privKeyBytes, &bccsp.IdemixRevocationKeyImportOpts{Temporary: true})
	if err != nil {
		return errors.Wrapf(err, "Failed to import revocation private key")
	}

	_, err = rk.CSP.KeyImport(pubKeyBytes, &bccsp.IdemixRevocationPublicKeyImportOpts{Temporary: true})
	if err != nil {
		return errors.Wrapf(err, "Failed to import revocation public key")
	}

	rk.key = revPrivKey
	return nil
}

// Store stores the CA's Idemix public and private key to the location
// specified by pubKeyFile and secretKeyFile attributes, respectively
func (rk *caIdemixRevocationKey) Store() error {
	pk := rk.GetKey()
	if pk == nil {
		return errors.New("Revocation key is not set")
	}

	privKeyBytes, err := pk.Bytes()
	if err != nil {
		return errors.Wrapf(err, "Failed to serialise revocation private key")
	}

	pubKey, err := pk.PublicKey()
	if err != nil {
		return errors.Wrapf(err, "Failed to convert revocation private key to public")
	}

	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return errors.Wrapf(err, "Failed to serialise revocation public key")
	}

	pubKeyBytes = pem.EncodeToMemory(&pem.Block{Type: "ECDSA Public Key", Bytes: pubKeyBytes})

	err = util.WriteFile(rk.privateKeyFile, []byte(privKeyBytes), 0644)
	if err != nil {
		log.Errorf("Failed to store revocation private key: %s", err.Error())
		return errors.Wrapf(err, "Failed to store revocation private key at %s", rk.privateKeyFile)
	}

	err = util.WriteFile(rk.pubKeyFile, []byte(pubKeyBytes), 0644)
	if err != nil {
		log.Errorf("Failed to store revocation public key: %s", err.Error())
		return errors.Wrapf(err, "Failed to store revocation public key at %s", rk.pubKeyFile)
	}

	log.Infof("The revocation key was successfully stored. The public key is at: %s, private key is at: %s",
		rk.pubKeyFile, rk.privateKeyFile)
	return nil
}

// GetKey returns revocation key
func (rk *caIdemixRevocationKey) GetKey() bccsp.Key {
	return rk.key
}

// SetKey sets revocation key
func (rk *caIdemixRevocationKey) SetKey(key bccsp.Key) {
	rk.key = key
}

// SetNewKey creates new revocation key and sets it in this object
func (rk *caIdemixRevocationKey) SetNewKey() (err error) {
	RevocationKey, err := rk.CSP.KeyGen(&bccsp.IdemixRevocationKeyGenOpts{Temporary: true})
	if err != nil {
		return err
	}

	rk.key = RevocationKey
	return nil
}

// EncodeKeys encodes ECDSA key pair to PEM encoding
func EncodeKeys(privateKey, publicKey types.Key) ([]byte, []byte, error) {
	privateKeyBytes, err := privateKey.Bytes()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to encode private key")
	}

	publicKeyBytes, err := publicKey.Bytes()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to encode public key")
	}

	publicKeyBytes = pem.EncodeToMemory(&pem.Block{Type: "ECDSA Public Key", Bytes: publicKeyBytes})

	return privateKeyBytes, publicKeyBytes, nil
}

// DecodeKeys decodes ECDSA key pair that are pem encoded
func DecodeKeys(privateKeyBytes, publicKeyBytes []byte, csp types.BCCSP) (types.Key, types.Key, error) {
	privateKey, err := csp.KeyImport(privateKeyBytes, &types.IdemixRevocationKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse private key bytes")
	}

	publicKey, err := csp.KeyImport(publicKeyBytes, &types.IdemixRevocationPublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse public key bytes")
	}

	return privateKey, publicKey, nil
}
