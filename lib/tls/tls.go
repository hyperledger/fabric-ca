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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"github.com/cloudflare/cfssl/log"
)

// ServerTLSConfig defines key material for a TLS server
type ServerTLSConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	KeyFile  string `json:"keyfile"`
	CertFile string `json:"certfile"`
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled   bool         `json:"enabled,omitempty"`
	CertFiles []string     `json:"certfiles"`
	Client    KeyCertFiles `json:"client"`
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  string `json:"keyfile"`
	CertFile string `json:"certfile"`
}

// GetClientTLSConfig creates a tls.Config object from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig) (*tls.Config, error) {
	//if !cfg.Enabled {
	//	return nil, nil
	//}
	var certs []tls.Certificate

	log.Debugf("CA Files: %s\n", cfg.CertFiles)
	log.Debugf("Client Cert File: %s\n", cfg.Client.CertFile)
	log.Debugf("Client Key File: %s\n", cfg.Client.KeyFile)
	clientCert, err := tls.LoadX509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile)
	if err != nil {
		log.Debugf("Client Cert or Key not provided, if server requires mutual TLS, the connection will fail [error: %s]", err)
	}

	certs = append(certs, clientCert)

	rootCAPool := x509.NewCertPool()

	if len(cfg.CertFiles) == 0 {
		log.Debug("No CA cert files provided. If server requires TLS, connection will fail")
	}

	for _, cacert := range cfg.CertFiles {
		caCert, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, err
		}
		ok := rootCAPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("Failed to process certificate from file %s", cacert)
		}
	}

	config := &tls.Config{
		Certificates: certs,
		RootCAs:      rootCAPool,
	}

	return config, nil
}
