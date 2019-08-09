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

package util_test

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	. "github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-ca/util/mocks"
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
	opts.SwOpts.Ephemeral = false
	csp, err = factory.GetBCCSPFromOpts(opts)
	if err != nil {
		fmt.Printf("Could not initialize BCCSP Factories [%s]", err)
		return -1
	}

	return m.Run()
}

func testKeyGenerate(t *testing.T, kr csr.KeyRequest, mustFail bool) {
	req := csr.CertificateRequest{
		KeyRequest: kr,
	}

	key, cspSigner, err := BCCSPKeyRequestGenerate(&req, csp)
	if mustFail {
		if err == nil {
			t.Fatalf("BCCSPKeyRequestGenerate should had failed")
		}
	} else {
		if err != nil {
			t.Fatalf("BCCSPKeyRequestGenerate failed: %s", err)
		}
		if key == nil {
			t.Fatalf("BCCSPKeyRequestGenerate key cannot be nil")
		}
		if cspSigner == nil {
			t.Fatalf("BCCSPKeyRequestGenerate cspSigner cannot be nil")
		}
	}
}

func TestGetDefaultBCCSP(t *testing.T) {
	csp := GetDefaultBCCSP()
	if csp == nil {
		t.Fatal("Failed to get default BCCSP")
	}
}

func TestInitBCCSP(t *testing.T) {
	mspDir := "msp"
	var opts *factory.FactoryOpts
	_, err := InitBCCSP(&opts, "", mspDir)
	if err != nil {
		t.Fatalf("Failed initialization 1 of BCCSP: %s", err)
	}
	cfg := &factory.FactoryOpts{ProviderName: "SW"}
	_, err = InitBCCSP(&cfg, "msp2", mspDir)
	if err != nil {
		t.Fatalf("Failed initialization 2 of BCCSP: %s", err)
	}
	_, err = InitBCCSP(nil, "", mspDir)
	if err == nil {
		t.Fatalf("Initialization 3 of BCCSP should have failed but did not")
	}
}

func TestKeyGenerate(t *testing.T) {
	t.Run("256", func(t *testing.T) { testKeyGenerate(t, csr.NewBasicKeyRequest(), false) })
	t.Run("384", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "ecdsa", S: 384}, false) })
	t.Run("521", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "ecdsa", S: 521}, true) })
	t.Run("521", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "ecdsa", S: 224}, true) })
	t.Run("512", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 512}, true) })
	t.Run("1024", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 1024}, true) })
	t.Run("2048", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 2048}, false) })
	t.Run("3072", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 3072}, false) })
	t.Run("4096", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 4096}, false) })
	t.Run("4097", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 4097}, true) })
	t.Run("10000", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{A: "rsa", S: 10000}, true) })
	t.Run("empty", func(t *testing.T) { testKeyGenerate(t, &csr.BasicKeyRequest{}, true) })
	t.Run("nil", func(t *testing.T) { testKeyGenerate(t, nil, false) })
}

func testGetSignerFromCertFile(t *testing.T, keyFile, certFile string, mustFail int) {
	key, err := ImportBCCSPKeyFromPEM(keyFile, csp, false)
	if mustFail == 1 {
		if err == nil {
			t.Fatalf("ImportBCCSPKeyFromPEM should had failed")
		}
		return
	}

	if err != nil {
		t.Fatalf("ImportBCCSPKeyFromPEM failed: %s", err)
	}
	if key == nil {
		t.Fatalf("ImportBCCSPKeyFromPEM key cannot be nil")
	}

	key, signer, cert, err := GetSignerFromCertFile(certFile, csp)
	if mustFail == 2 {
		if err == nil {
			t.Fatalf("ImportBCCSPKeyFromPEM should had failed")
		}
	} else {
		if err != nil {
			t.Fatalf("GetSignerFromCertFile failed: %s", err)
		}
		if key == nil {
			t.Fatalf("GetSignerFromCertFile key cannot be nil")
		}
		if signer == nil {
			t.Fatalf("GetSignerFromCertFile signer cannot be nil")
		}
		if cert == nil {
			t.Fatalf("GetSignerFromCertFile cert cannot be nil")
		}
	}

	cer, err := LoadX509KeyPair(certFile, keyFile, csp)
	if mustFail == 2 {
		if err == nil {
			t.Fatalf("LoadX509KeyPair should had failed")
		}
	} else {
		if err != nil {
			t.Fatalf("LoadX509KeyPair failed: %s", err)
		}
		if cer.Certificate[0] == nil {
			t.Fatalf("LoadX509KeyPair cert cannot be nil")
		}
	}
}

func TestGetSignerFromCertFile(t *testing.T) {
	t.Run("ec", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec-key.pem", "../testdata/ec.pem", 0)
	})
	t.Run("nokey", func(t *testing.T) {
		testGetSignerFromCertFile(t, "doesnotexist.pem", "../testdata/ec.pem", 1)
	})
	t.Run("nocert", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec-key.pem", "doesnotexist.pem", 2)
	})
	t.Run("cert4key", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec.pem", "../testdata/ec.pem", 1)
	})
	t.Run("rsa", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/rsa-key.pem", "../testdata/rsa.pem", 1)
	})
	t.Run("wrongcert", func(t *testing.T) {
		testGetSignerFromCertFile(t, "../testdata/ec-key.pem", "../testdata/test.pem", 2)
	})
}

func TestBccspBackedSigner(t *testing.T) {
	signer, err := BccspBackedSigner("", "", nil, csp)
	if signer != nil {
		t.Fatalf("BccspBackedSigner should not be valid for empty cert: %s", err)
	}

	signer, err = BccspBackedSigner("doesnotexist.pem", "", nil, csp)
	if err == nil {
		t.Fatal("BccspBackedSigner should had failed to load cert")
	}
	if signer != nil {
		t.Fatal("BccspBackedSigner should not be valid for non-existent cert")
	}

	signer, err = BccspBackedSigner("../testdata/ec.pem", "../testdata/ec-key.pem", nil, csp)
	if signer == nil {
		t.Fatalf("BccspBackedSigner should had found cert: %s", err)
	}
}

func TestGetSignerFromCertInvalidArgs(t *testing.T) {
	_, _, err := GetSignerFromCert(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CSP was not initialized")

	csp := &mocks.BCCSP{}
	csp.On("KeyImport", (*x509.Certificate)(nil), &bccsp.X509PublicKeyImportOpts{Temporary: true}).Return(bccsp.Key(nil), errors.New("mock key import error"))
	_, _, err = GetSignerFromCert(nil, csp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to import certificate's public key: mock key import error")
}

func TestClean(t *testing.T) {
	os.RemoveAll("csp")
}
