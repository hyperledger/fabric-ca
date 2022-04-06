/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util_test

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	. "github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/stretchr/testify/assert"
)

var csp bccsp.BCCSP

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	err := factory.InitFactories(nil)
	if err != nil {
		fmt.Printf("Could not initialize BCCSP factory interfaces [%s]", err)
		return -1
	}

	tmpDir, err := ioutil.TempDir("", "keystore")
	if err != nil {
		fmt.Printf("Could not create keystore directory [%s]", err)
		return -1
	}
	defer os.RemoveAll(tmpDir)

	opts := factory.GetDefaultOpts()
	opts.SwOpts.FileKeystore = &factory.FileKeystoreOpts{KeyStorePath: tmpDir}
	csp, err = factory.GetBCCSPFromOpts(opts)
	if err != nil {
		fmt.Printf("Could not initialize BCCSP Factories [%s]", err)
		return -1
	}

	return m.Run()
}

func TestInitBCCSP(t *testing.T) {
	mspDir := t.TempDir()

	var opts *factory.FactoryOpts
	_, err := InitBCCSP(&opts, "", mspDir)
	assert.NoError(t, err, "first initialization of BCCSP failed")

	cfg := &factory.FactoryOpts{ProviderName: "SW"}
	_, err = InitBCCSP(&cfg, "msp2", mspDir)
	assert.NoError(t, err, "second initialization of BCCSP failed")

	_, err = InitBCCSP(nil, "", mspDir)
	assert.Error(t, err, "third initialization  of BCCSP should have failed")
}

func TestGetDefaultBCCSP(t *testing.T) {
	csp := GetDefaultBCCSP()
	assert.NotNil(t, csp, "failed to get default BCCSP")
}

func testKeyGenerate(t *testing.T, kr *csr.KeyRequest, mustFail bool) {
	req := csr.CertificateRequest{KeyRequest: kr}
	key, cspSigner, err := BCCSPKeyRequestGenerate(&req, csp)
	if mustFail {
		assert.Error(t, err, "BCCSPKeyRequestGenerate should fail")
		return
	}

	assert.NoError(t, err, "BCCSPKeyRequestGenerate failed")
	assert.NotNil(t, key, "created key must not be nil")
	assert.NotNil(t, cspSigner, "created signer must not be nil")
}

func TestKeyGenerate(t *testing.T) {
	t.Run("256", func(t *testing.T) { testKeyGenerate(t, csr.NewKeyRequest(), false) })
	t.Run("384", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "ecdsa", S: 384}, false) })
	t.Run("521", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "ecdsa", S: 521}, true) })
	t.Run("521", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "ecdsa", S: 224}, true) })
	t.Run("512", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "rsa", S: 512}, true) })
	t.Run("1024", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "rsa", S: 1024}, true) })
	t.Run("2048", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "rsa", S: 2048}, false) })
	t.Run("3072", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "rsa", S: 3072}, false) })
	t.Run("4096", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "rsa", S: 4096}, false) })
	t.Run("4097", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "rsa", S: 4097}, true) })
	t.Run("10000", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{A: "rsa", S: 10000}, true) })
	t.Run("empty", func(t *testing.T) { testKeyGenerate(t, &csr.KeyRequest{}, true) })
	t.Run("nil", func(t *testing.T) { testKeyGenerate(t, nil, false) })
}

func testGetSignerFromCertFile(t *testing.T, keyFile, certFile string, mustFail int) {
	key, err := ImportBCCSPKeyFromPEM(keyFile, csp, false)
	if mustFail == 1 {
		assert.Error(t, err, "ImportBCCSPKeyFromPEM should had failed")
		return
	}

	assert.NoError(t, err, "ImportBCCSPKeyFromPEM failed")
	assert.NotNil(t, key, "imported key must not be nil")

	key, signer, cert, err := GetSignerFromCertFile(certFile, csp)
	if mustFail == 2 {
		assert.Error(t, err, "GetSignerFromCertFile should had failed")
	} else {
		assert.NoError(t, err, "GetSignerFromCertFile failed")
		assert.NotNil(t, key, "key from GetSignerFromCertFile must not be nil")
		assert.NotNil(t, signer, "signer from GetSignerFromCertFile must not be nil")
		assert.NotNil(t, cert, "cert  from GetSignerFromCertFile must not be nil")
	}

	cer, err := LoadX509KeyPair(certFile, keyFile, csp)
	if mustFail == 2 {
		assert.Error(t, err, "LoadX509KeyPair should had failed")
	} else {
		assert.NoError(t, err, "LoadX509KeyPair failed")
		assert.NotNil(t, cer.Certificate[0], "LoadX509KeyPair cert cannot be nil")
	}
}

func TestGetSignerFromCertFile(t *testing.T) {
	t.Run("ec", func(t *testing.T) {
		testGetSignerFromCertFile(t, filepath.Join("testdata", "ec-key.pem"), filepath.Join("testdata", "ec.pem"), 0)
	})
	t.Run("nokey", func(t *testing.T) {
		testGetSignerFromCertFile(t, "doesnotexist.pem", filepath.Join("testdata", "ec.pem"), 1)
	})
	t.Run("nocert", func(t *testing.T) {
		testGetSignerFromCertFile(t, filepath.Join("testdata", "ec-key.pem"), "doesnotexist.pem", 2)
	})
	t.Run("cert4key", func(t *testing.T) {
		testGetSignerFromCertFile(t, filepath.Join("testdata", "ec.pem"), filepath.Join("testdata", "ec.pem"), 1)
	})
	t.Run("rsa", func(t *testing.T) {
		testGetSignerFromCertFile(t, filepath.Join("testdata", "rsa-key.pem"), filepath.Join("testdata", "rsa.pem"), 1)
	})
	t.Run("wrongcert", func(t *testing.T) {
		testGetSignerFromCertFile(t, filepath.Join("testdata", "ec-key.pem"), filepath.Join("testdata", "test.pem"), 2)
	})
}

func TestBccspBackedSigner(t *testing.T) {
	signer, err := BccspBackedSigner("", "", nil, csp)
	assert.Error(t, err, "BccspBackedSigner should have failed for empty cert")
	assert.Nil(t, signer, "BccspBackedSigner must be nil for empty cert")

	signer, err = BccspBackedSigner("doesnotexist.pem", "", nil, csp)
	assert.Error(t, err, "BccspBackedSigner should have failed to load cert")
	assert.Nil(t, signer, "BccspBackedSigner must be nil for non-existent cert")

	signer, err = BccspBackedSigner(filepath.Join("testdata", "ec.pem"), filepath.Join("testdata", "ec-key.pem"), nil, csp)
	assert.NoError(t, err, "BccspBackedSigner failed to load certificate")
	assert.NotNil(t, signer, "BccspBackedSigner should had found cert")
}

func TestGetSignerFromCertInvalidArgs(t *testing.T) {
	_, _, err := GetSignerFromCert(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CSP was not initialized")

	_, _, err = GetSignerFromCert(&x509.Certificate{}, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to import certificate's public key:")
	assert.Contains(t, err.Error(), "Certificate's public key type not recognized.")
}
