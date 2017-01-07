/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package csp

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/hyperledger/fabric/core/crypto/bccsp"
	"github.com/hyperledger/fabric/core/crypto/bccsp/factory"
	"github.com/hyperledger/fabric/core/crypto/bccsp/signer"
	"github.com/hyperledger/fabric/core/crypto/bccsp/sw"
)

const (
	// SKIPEM is the PEM type to identify an SKI (Subject Key Identifier)
	SKIPEM = "BCCSP SKI"
)

// Get returns an instance of the CSP (Crypto Service Provider)
// given some config.  If config is nil, return the default instance.
func Get(cfg *Config) (bccsp.BCCSP, error) {
	if cfg != nil {
		return cfg.Get()
	}
	return factory.GetDefault()
}

// Config is the configuration for CSP (Crypto Service Provider)
// which allows plugging in support for HSMs (Hardware Service Modules)
// Currently supported types are: 'software'
type Config struct {
	SW *SWConfig `json:"software,omitempty"`
}

// Get returns the instance of BCCSP for the config
func (c *Config) Get() (bccsp.BCCSP, error) {
	if c.SW != nil {
		return c.SW.Get()
	}
	return nil, fmt.Errorf("Invalid configuration; must contain one of: 'software'")
}

// SWConfig is configuration for the software implementation of CSP
type SWConfig struct {
	KeyStoreDir   string `json:"key_store_dir,omitempty"`
	HashFamily    string `json:"hash_family,omitempty"`
	SecurityLevel int    `json:"security_level,omitempty"`
	Ephemeral     bool   `json:"ephemeral,omitempty"`
}

// Get returns the instance of the software CSP
func (sc *SWConfig) Get() (bccsp.BCCSP, error) {
	// Set defaults
	keyStoreDir := getStrVal(sc.KeyStoreDir, path.Join(os.Getenv("HOME"), ".bccsp", "ks"))
	hashFamily := getStrVal(sc.HashFamily, "SHA2")
	secLevel := getIntVal(sc.SecurityLevel, 256)
	// Init keystore
	ks := &sw.FileBasedKeyStore{}
	err := ks.Init(nil, keyStoreDir, false)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing software key store: %s", err)
	}
	// Return BCCSP instance
	bccspOpts := &factory.SwOpts{KeyStore: ks, SecLevel: secLevel, HashFamily: hashFamily, Ephemeral_: sc.Ephemeral}
	return factory.GetBCCSP(bccspOpts)
}

// GetSignerFromSKIFile returns a signer for an SKI file
func GetSignerFromSKIFile(skiFile string, csp bccsp.BCCSP) (crypto.Signer, error) {
	if csp == nil {
		return nil, fmt.Errorf("csp is nil")
	}
	keyBuff, err := ioutil.ReadFile(skiFile)
	if err != nil {
		return nil, fmt.Errorf("Could not read SKI file [%s]: %s", skiFile, err)
	}

	block, _ := pem.Decode(keyBuff)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding SKI file [%s]", skiFile)
	}

	if block.Type != SKIPEM {
		return nil, fmt.Errorf("Invalid PEM type in file %s; expecting '%s' but found '%s'", skiFile, SKIPEM, block.Type)
	}

	privateKey, err := csp.GetKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to get key from SKI file [%s]: %s", skiFile, err)
	}

	signer := &signer.CryptoSigner{}
	if err = signer.Init(csp, privateKey); err != nil {
		return nil, fmt.Errorf("Failed to initialize signer from SKI file [%s]: %s", skiFile, err)
	}

	return signer, nil
}

// GenRootKey generates a new root key
func GenRootKey(csp bccsp.BCCSP) (bccsp.Key, error) {
	opts := &bccsp.AES256KeyGenOpts{Temporary: true}
	return csp.KeyGen(opts)
}

func getStrVal(val, def string) string {
	if val != "" {
		return val
	}
	return def
}

func getIntVal(val, def int) int {
	if val != 0 {
		return val
	}
	return def
}
