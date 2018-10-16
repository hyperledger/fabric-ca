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

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	configDir   = "../../testdata"
	caCert      = "root.pem"
	certFile    = "tls_client-cert.pem"
	keyFile     = "tls_client-key.pem"
	expiredCert = "../../testdata/expiredcert.pem"
)

type testTLSConfig struct {
	TLS *ClientTLSConfig
}

func TestGetClientTLSConfig(t *testing.T) {

	cfg := &ClientTLSConfig{
		CertFiles: []string{"root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}

	err := AbsTLSClient(cfg, configDir)
	if err != nil {
		t.Errorf("Failed to get absolute path for client TLS config: %s", err)
	}

	_, err = GetClientTLSConfig(cfg, nil)
	if err != nil {
		t.Errorf("Failed to get TLS Config: %s", err)
	}

}

func TestGetClientTLSConfigInvalidArgs(t *testing.T) {
	// 1.
	cfg := &ClientTLSConfig{
		CertFiles: []string{"root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "no_tls_client-key.pem",
			CertFile: "no_tls_client-cert.pem",
		},
	}
	_, err := GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "open no_tls_client-cert.pem: no such file or directory")

	// 2.
	cfg = &ClientTLSConfig{
		CertFiles: nil,
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No trusted root certificates for TLS were provided")

	// 3.
	cfg = &ClientTLSConfig{
		CertFiles: nil,
		Client: KeyCertFiles{
			KeyFile:  "no-tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no-tls_client-key.pem: no such file or directory")

	// 4.
	cfg = &ClientTLSConfig{
		CertFiles: nil,
		Client: KeyCertFiles{
			KeyFile:  "",
			CertFile: "",
		},
	}
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No trusted root certificates for TLS were provided")

	// 5.
	cfg = &ClientTLSConfig{
		CertFiles: []string{"no-root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no-root.pem: no such file or directory")
}

func TestAbsServerTLSConfig(t *testing.T) {
	cfg := &ServerTLSConfig{
		KeyFile:  "tls_client-key.pem",
		CertFile: "tls_client-cert.pem",
		ClientAuth: ClientAuth{
			CertFiles: []string{"root.pem"},
		},
	}

	err := AbsTLSServer(cfg, configDir)
	if err != nil {
		t.Errorf("Failed to get absolute path for server TLS config: %s", err)
	}
}

func TestCheckCertDates(t *testing.T) {
	err := checkCertDates(expiredCert)
	if err == nil {
		assert.Error(t, errors.New("Expired certificate should have resulted in an error"))
	}

	err = createTestCertificate()
	if err != nil {
		assert.Error(t, err)
	}

	err = checkCertDates("notbefore.pem")
	if err == nil {
		assert.Error(t, errors.New("Future valid certificate should have resulted in an error"))
	}
	if err != nil {
		assert.Contains(t, err.Error(), "Certificate provided not valid until later date")
	}

	os.Remove("notbefore.pem")
}

func createTestCertificate() error {
	// Dynamically create a certificate with future valid date for testing purposes
	certTemplate := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          big.NewInt(1234),
		NotBefore:             time.Now().Add(time.Hour * 24),
		NotAfter:              time.Now().Add(time.Hour * 48),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("Error occurred during key generation: %s", err)
	}
	publickey := &privatekey.PublicKey
	// create a self-signed certificate. template = parent
	var parent = certTemplate
	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, publickey, privatekey)
	if err != nil {
		return fmt.Errorf("Error occurred during certificate creation: %s", err)
	}

	pemfile, _ := os.Create("notbefore.pem")
	var pemkey = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	pem.Encode(pemfile, pemkey)
	pemfile.Close()

	return nil
}
