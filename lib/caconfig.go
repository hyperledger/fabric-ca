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
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/ldap"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
)

const (
	// defaultCACfgTemplate is the a CA's default configuration file template
	defaultCACfgTemplate = `
#############################################################################
# This file contains information specific to a single Certificate Authority (CA).
# A single fabric-ca-server can service multiple CAs.  The server's configuration
# file contains configuration information for the default CA, and each of these
# CA-specific files define configuration settings for a non-default CA.
#
# The only required configuration item in each CA-specific file is a unique
# CA name (see "ca.name" below).  Each CA name in the same fabric-ca-server
# must be unique. All other configuration settings needed for this CA are
# taken from the default CA settings, or you may override those settings by
# adding the setting to this file.
#
# For example, you should provide a different username and password for the
# bootstrap identity as found in the "identities" subsection of the "registry"
# section.
#
# See the server's configuration file for comments on all settings.
# All settings pertaining to the server's listening endpoint are by definition
# server-specific and so will be ignored in a CA configuration file.
#############################################################################
ca:
  # Name of this CA
  name: <<<CANAME>>>
  # The CA certificate file
  certfile: ca-cert.pem
  # The CA key file
  keyfile: ca-key.pem

#############################################################################
#  Database section
#  Supported types are: "sqlite3", "postgres", and "mysql".
#  The datasource value depends on the type.
#  If the type is "sqlite3", the datasource value is a file name to use
#  as the database store.  Since "sqlite3" is an embedded database, it
#  may not be used if you want to run the fabric-ca-server in a cluster.
#  To run the fabric-ca-server in a cluster, you must choose "postgres"
#  or "mysql".
#############################################################################
db:
  datasource: <<<DATASOURCE>>>

###########################################################################
#  Certificate Signing Request section for generating the CA certificate
###########################################################################
csr:
  cn: <<<COMMONNAME>>>
`
)

// CAConfig is the CA instance's config
// The tags are recognized by the RegisterFlags function in fabric-ca/lib/util.go
// and are as follows:
// "def" - the default value of the field;
// "opt" - the optional one character short name to use on the command line;
// "help" - the help message to display on the command line;
// "skip" - to skip the field.
type CAConfig struct {
	Version      string `skip:"true"`
	Cfg          cfgOptions
	CA           CAInfo
	Signing      *config.Signing
	CSR          api.CSRInfo
	Registry     CAConfigRegistry
	Affiliations map[string]interface{}
	LDAP         ldap.Config
	DB           CAConfigDB
	CSP          *factory.FactoryOpts `mapstructure:"bccsp"`
	// Optional client config for an intermediate server which acts as a client
	// of the root (or parent) server
	Client       *ClientConfig
	Intermediate IntermediateCA
	CRL          CRLConfig
}

// cfgOptions is a CA configuration that allows for setting different options
type cfgOptions struct {
	Identities   identitiesOptions
	Affiliations affiliationsOptions
}

// identitiesOptions are options that are related to identities
type identitiesOptions struct {
	AllowRemove bool `help:"Enables removal of identities dynamically"`
}

// affiliationsOptions are options that are related to affiliations
type affiliationsOptions struct {
	AllowRemove bool `help:"Enables removal of affiliations dynamically"`
}

// CAInfo is the CA information on a fabric-ca-server
type CAInfo struct {
	Name      string `opt:"n" help:"Certificate Authority name"`
	Keyfile   string `help:"PEM-encoded CA key file"`
	Certfile  string `def:"ca-cert.pem" help:"PEM-encoded CA certificate file"`
	Chainfile string `def:"ca-chain.pem" help:"PEM-encoded CA chain file"`
}

// CAConfigDB is the database part of the server's config
type CAConfigDB struct {
	Type       string `def:"sqlite3" help:"Type of database; one of: sqlite3, postgres, mysql"`
	Datasource string `def:"fabric-ca-server.db" help:"Data source which is database specific"`
	TLS        tls.ClientTLSConfig
}

// Implements Stringer interface for CAConfigDB
// Calls util.StructToString to convert the CAConfigDB struct to
// string and masks the password from the database URL. Returns
// resulting string.
func (c CAConfigDB) String() string {
	str := util.StructToString(&c)
	return dbutil.MaskDBCred(str)
}

// CAConfigRegistry is the registry part of the server's config
type CAConfigRegistry struct {
	MaxEnrollments int `def:"-1" help:"Maximum number of enrollments; valid if LDAP not enabled"`
	Identities     []CAConfigIdentity
}

// CAConfigIdentity is identity information in the server's config
type CAConfigIdentity struct {
	Name           string `mask:"username"`
	Pass           string `mask:"password"`
	Type           string
	Affiliation    string
	MaxEnrollments int
	Attrs          map[string]string
}

// ParentServer contains URL for the parent server and the name of CA inside
// the server to connect to
type ParentServer struct {
	URL    string `opt:"u" help:"URL of the parent fabric-ca-server (e.g. http://<username>:<password>@<address>:<port)" mask:"url"`
	CAName string `help:"Name of the CA to connect to on fabric-ca-server"`
}

// IntermediateCA contains parent server information, TLS configuration, and
// enrollment request for an intermetiate CA
type IntermediateCA struct {
	ParentServer ParentServer
	TLS          tls.ClientTLSConfig
	Enrollment   api.EnrollmentRequest
}

// CRLConfig contains configuration options used by the gencrl request handler
type CRLConfig struct {
	// Specifies expiration for the CRL generated by the gencrl request
	// The number of hours specified by this property is added to the UTC time, resulting time
	// is used to set the 'Next Update' date of the CRL
	Expiry time.Duration `def:"24h" help:"Expiration for the CRL generated by the gencrl request"`
}

func (cc CAConfigIdentity) String() string {
	return util.StructToString(&cc)
}

func (parent ParentServer) String() string {
	return util.StructToString(&parent)
}
