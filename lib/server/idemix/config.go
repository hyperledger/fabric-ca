/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"path/filepath"

	"github.com/hyperledger/fabric-ca/util"
)

const (
	// DefaultIssuerPublicKeyFile is the default name of the file that contains issuer public key
	DefaultIssuerPublicKeyFile = "IssuerPublicKey"
	// DefaultIssuerSecretKeyFile is the default name of the file that contains issuer secret key
	DefaultIssuerSecretKeyFile = "IssuerSecretKey"
	// DefaultRevocationPublicKeyFile is the name of the file where revocation public key is stored
	DefaultRevocationPublicKeyFile = "IssuerRevocationPublicKey"
	// DefaultRevocationPrivateKeyFile is the name of the file where revocation private key is stored
	DefaultRevocationPrivateKeyFile = "IssuerRevocationPrivateKey"
	// KeystoreDir is the keystore directory where all keys are stored. It is relative to the server home directory.
	KeystoreDir = "msp/keystore"
)

// Config encapsulates Idemix related the configuration options
type Config struct {
	IssuerPublicKeyfile      string `def:"IssuerPublicKey" skip:"true" help:"Name of the file that contains marshalled bytes of CA's Idemix issuer public key"`
	IssuerSecretKeyfile      string `def:"IssuerSecretKey" skip:"true" help:"Name of the file that contains CA's Idemix issuer secret key"`
	RevocationPublicKeyfile  string `def:"IssuerRevocationPublicKey" skip:"true" help:"Name of the file that contains Idemix issuer revocation public key"`
	RevocationPrivateKeyfile string `def:"IssuerRevocationPrivateKey" skip:"true" help:"Name of the file that contains Idemix issuer revocation private key"`
	RHPoolSize               int    `def:"100" help:"Specifies revocation handle pool size"`
	NonceExpiration          string `def:"15s" help:"Duration after which a nonce expires"`
	NonceSweepInterval       string `def:"15m" help:"Interval at which expired nonces are deleted"`
}

// InitConfig initializes Idemix configuration
func (c *Config) init(homeDir string) error {
	c.IssuerPublicKeyfile = DefaultIssuerPublicKeyFile
	c.IssuerSecretKeyfile = filepath.Join(KeystoreDir, DefaultIssuerSecretKeyFile)
	c.RevocationPublicKeyfile = DefaultRevocationPublicKeyFile
	c.RevocationPrivateKeyfile = filepath.Join(KeystoreDir, DefaultRevocationPrivateKeyFile)
	if c.RHPoolSize == 0 {
		c.RHPoolSize = DefaultRevocationHandlePoolSize
	}
	if c.NonceExpiration == "" {
		c.NonceExpiration = DefaultNonceExpiration
	}
	if c.NonceSweepInterval == "" {
		c.NonceSweepInterval = DefaultNonceSweepInterval
	}
	fields := []*string{
		&c.IssuerPublicKeyfile,
		&c.IssuerSecretKeyfile,
		&c.RevocationPublicKeyfile,
		&c.RevocationPrivateKeyfile,
	}
	err := util.MakeFileNamesAbsolute(fields, homeDir)
	if err != nil {
		return err
	}
	return nil
}
