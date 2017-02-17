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

package lib_test

import (
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/lib"
)

const (
	keyfile  = "key.pem"
	certfile = "cert.pem"
)

func TestServerInit(t *testing.T) {
	server := &lib.Server{}
	err := server.Init(false)
	if err == nil {
		t.Errorf("Server init with empty config should have failed")
	}
	server.Config = getServerConfig()
	err = server.Init(false)
	if err != nil {
		t.Errorf("Server init with empty home directory failed: %s", err)
	}
	server = getServer()
	err = server.Init(false)
	if err != nil {
		t.Errorf("Server init no renew failed: %s", err)
	}
	err = server.Init(true)
	if err != nil {
		t.Errorf("Server init renew failed: %s", err)
	}
}

func TestServerStartStop(t *testing.T) {
	server := getServer()
	err := server.Start()
	if err != nil {
		t.Errorf("Server start failed: %s", err)
	}
	time.Sleep(time.Second)
	err = server.Stop()
	if err != nil {
		t.Errorf("Server stop failed: %s", err)
	}
}

func TestCleanup(t *testing.T) {
	os.Remove(keyfile)
	os.Remove(certfile)
	os.Remove("fabric-ca-server.db")
}

func getServer() *lib.Server {
	return &lib.Server{
		HomeDir: ".",
		Config:  getServerConfig(),
	}
}

func getServerConfig() *lib.ServerConfig {
	return &lib.ServerConfig{
		Port: 7055,
		CA: lib.ServerConfigCA{
			Keyfile:  keyfile,
			Certfile: certfile,
		},
		CSR: csr.CertificateRequest{
			CN: "TestCN",
		},
	}
}
