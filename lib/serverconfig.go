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
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/lib/csp"
	"github.com/hyperledger/fabric-ca/lib/ldap"
	"github.com/hyperledger/fabric-ca/lib/tls"
)

const (
	// DefaultServerPort is the default listening port for the fabric-ca server
	DefaultServerPort = 7054

	// DefaultServerAddr is the default listening address for the fabric-ca server
	DefaultServerAddr = "0.0.0.0"
)

// ServerConfig is the fabric-ca server's config
type ServerConfig struct {
	Port         int
	Address      string
	TLS          tls.ServerTLSConfig
	Debug        bool
	CSP          *csp.Config
	CA           ServerConfigCA
	Signing      *config.Signing
	CSR          csr.CertificateRequest
	Registry     ServerConfigRegistry
	Affiliations map[string]interface{}
	LDAP         ldap.Config
	DB           ServerConfigDB
	Remote       string
}

// ServerConfigCA is the CA config for the fabric-ca server
type ServerConfigCA struct {
	Keyfile  string
	Certfile string
}

// ServerConfigDB is the database part of the server's config
type ServerConfigDB struct {
	Type       string
	Datasource string
	TLS        tls.ClientTLSConfig
}

// ServerConfigRegistry is the registry part of the server's config
type ServerConfigRegistry struct {
	MaxEnrollments int
	Identities     []ServerConfigIdentity
}

// ServerConfigIdentity is identity information in the server's config
type ServerConfigIdentity struct {
	ID             string
	Pass           string
	Type           string
	Affiliation    string
	MaxEnrollments int
	Attributes     map[string]string
}
