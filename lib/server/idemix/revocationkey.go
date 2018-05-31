/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

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
	// GetKey returns *ecdsa.PrivateKey that represents revocation public and private key pair
	GetKey() *ecdsa.PrivateKey
	// SetKey sets revocation public and private key
	SetKey(key *ecdsa.PrivateKey)
	// SetNewKey creates new revocation public and private key pair and sets them in this object
	SetNewKey() error
}

// caIdemixRevocationKey implements RevocationKey interface
type caIdemixRevocationKey struct {
	pubKeyFile     string
	privateKeyFile string
	key            *ecdsa.PrivateKey
	idemixLib      Lib
}

// NewRevocationKey returns an instance of an object that implements RevocationKey interface
func NewRevocationKey(pubKeyFile, privateKeyFile string, lib Lib) RevocationKey {
	return &caIdemixRevocationKey{
		pubKeyFile:     pubKeyFile,
		privateKeyFile: privateKeyFile,
		idemixLib:      lib,
	}
}

// Load loads the Issuer revocation public and private key from the location specified
// by pubKeyFile and privateKeyFile attributes, respectively
func (rk *caIdemixRevocationKey) Load() error {
	pubKeyBytes, err := ioutil.ReadFile(rk.pubKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read revocation public key from %s", rk.pubKeyFile)
	}
	if len(pubKeyBytes) == 0 {
		return errors.New("Revocation public key file is empty")
	}
	privKey, err := ioutil.ReadFile(rk.privateKeyFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read revocation private key from %s", rk.privateKeyFile)
	}
	if len(privKey) == 0 {
		return errors.New("Revocation private key file is empty")
	}
	pk, pubKey, err := DecodeKeys(privKey, pubKeyBytes)
	if err != nil {
		return errors.WithMessage(err, "Failed to decode revocation key")
	}
	pk.PublicKey = *pubKey
	rk.key = pk
	return nil
}

// Store stores the CA's Idemix public and private key to the location
// specified by pubKeyFile and secretKeyFile attributes, respectively
func (rk *caIdemixRevocationKey) Store() error {
	pk := rk.GetKey()
	if pk == nil {
		return errors.New("Revocation key is not set")
	}
	pkBytes, pubKeyBytes, err := EncodeKeys(pk, &pk.PublicKey)
	if err != nil {
		return errors.WithMessage(err, "Failed to encode revocation public key")
	}
	err = util.WriteFile(rk.privateKeyFile, []byte(pkBytes), 0644)
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
func (rk *caIdemixRevocationKey) GetKey() *ecdsa.PrivateKey {
	return rk.key
}

// SetKey sets revocation key
func (rk *caIdemixRevocationKey) SetKey(key *ecdsa.PrivateKey) {
	rk.key = key
}

// SetNewKey creates new revocation key and sets it in this object
func (rk *caIdemixRevocationKey) SetNewKey() (err error) {
	rk.key, err = rk.idemixLib.GenerateLongTermRevocationKey()
	return err
}

// EncodeKeys encodes ECDSA key pair to PEM encoding
func EncodeKeys(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, []byte, error) {
	encodedPK, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to encode ECDSA private key")
	}
	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})

	encodedPubKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to encode ECDSA public key")
	}
	pemEncodedPubKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedPubKey})
	return pemEncodedPK, pemEncodedPubKey, nil
}

// DecodeKeys decodes ECDSA key pair that are pem encoded
func DecodeKeys(pemEncodedPK, pemEncodedPubKey []byte) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncodedPK)
	if block == nil {
		return nil, nil, errors.New("Failed to decode ECDSA private key")
	}
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse ECDSA private key bytes")
	}
	blockPub, _ := pem.Decode(pemEncodedPubKey)
	if blockPub == nil {
		return nil, nil, errors.New("Failed to decode ECDSA public key")
	}
	key, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse ECDSA public key bytes")
	}
	publicKey := key.(*ecdsa.PublicKey)

	return pk, publicKey, nil
}
