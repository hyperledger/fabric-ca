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
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	configDir = "../../testdata"
	caCert    = "root.pem"
	certFile  = "tls_client-cert.pem"
	keyFile   = "tls_client-key.pem"
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

	AbsTLSClient(cfg, configDir)

	_, err := GetClientTLSConfig(cfg)
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
	_, err := GetClientTLSConfig(cfg)
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
	_, err = GetClientTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No CA certificate files provided")

	// 3.
	cfg = &ClientTLSConfig{
		CertFiles: nil,
		Client: KeyCertFiles{
			KeyFile:  "no-tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg)
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
	_, err = GetClientTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No CA certificate files provided")

	// 5.
	cfg = &ClientTLSConfig{
		CertFiles: []string{"no-root.pem"},
		Client: KeyCertFiles{
			KeyFile:  "tls_client-key.pem",
			CertFile: "tls_client-cert.pem",
		},
	}
	AbsTLSClient(cfg, configDir)
	_, err = GetClientTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no-root.pem: no such file or directory")

}
