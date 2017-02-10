/*
Copyright IBM Corp. 2017 All Rights Reserved.

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

package lib

import (
	"os"
	"testing"

	"github.com/cloudflare/cfssl/csr"
)

const (
	keyfile  = "key.pem"
	certfile = "cert.pem"
)

func TestServerInit(t *testing.T) {
	config := &ServerConfig{
		CA: ServerConfigCA{
			Keyfile:  keyfile,
			Certfile: certfile,
		},
		CSR: csr.CertificateRequest{
			CN: "TestCN",
		},
	}
	server := Server{
		HomeDir: ".",
		Config:  config,
	}
	err := server.Init(false)
	if err != nil {
		t.Errorf("Server init no renew failed: %s", err)
	}
	err = server.Init(true)
	if err != nil {
		t.Errorf("Server init renew failed: %s", err)
	}
}

func TestCleanup(t *testing.T) {
	os.Remove(keyfile)
	os.Remove(certfile)
}
