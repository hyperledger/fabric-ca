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

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	longName     = "Hyperledger Fabric Certificate Authority Server"
	shortName    = "fabric-ca server"
	cmdName      = "fabric-ca-server"
	envVarPrefix = "FABRIC_CA_SERVER"
	homeEnvVar   = "FABRIC_CA_SERVER_HOME"
	caNameReqMsg = "ca.name property is required but is missing from the configuration file"
)

const (
	defaultCfgTemplate = `#############################################################################
#   This is a configuration file for the fabric-ca-server command.
#
#   COMMAND LINE ARGUMENTS AND ENVIRONMENT VARIABLES
#   ------------------------------------------------
#   Each configuration element can be overridden via command line
#   arguments or environment variables.  The precedence for determining
#   the value of each element is as follows:
#   1) command line argument
#      Examples:
#      a) --port 443
#         To set the listening port
#      b) --ca-keyfile ../mykey.pem
#         To set the "keyfile" element in the "ca" section below;
#         note the '-' separator character.
#   2) environment variable
#      Examples:
#      a) FABRIC_CA_SERVER_PORT=443
#         To set the listening port
#      b) FABRIC_CA_SERVER_CA_KEYFILE="../mykey.pem"
#         To set the "keyfile" element in the "ca" section below;
#         note the '_' separator character.
#   3) configuration file
#   4) default value (if there is one)
#      All default values are shown beside each element below.
#
#   FILE NAME ELEMENTS
#   ------------------
#   The value of all fields whose name ends with "file" or "files" are
#   name or names of other files.
#   For example, see "tls.certfile" and "tls.clientauth.certfiles".
#   The value of each of these fields can be a simple filename, a
#   relative path, or an absolute path.  If the value is not an
#   absolute path, it is interpretted as being relative to the location
#   of this configuration file.
#
#############################################################################

# Server's listening port (default: 7054)
port: 7054

# Enables debug logging (default: false)
debug: false

# Size limit of an acceptable CRL in bytes (default: 512000)
crlsizelimit: 512000

#############################################################################
#  TLS section for the server's listening port
#
#  The following types are supported for client authentication: NoClientCert,
#  RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven,
#  and RequireAndVerifyClientCert.
#
#  Certfiles is a list of root certificate authorities that the server uses
#  when verifying client certificates.
#############################################################################
tls:
  # Enable TLS (default: false)
  enabled: false
  # TLS for the server's listening port
  certfile: tls-cert.pem
  keyfile:
  clientauth:
    type: noclientcert
    certfiles:

#############################################################################
#  The CA section contains information related to the Certificate Authority
#  including the name of the CA, which should be unique for all members
#  of a blockchain network.  It also includes the key and certificate files
#  used when issuing enrollment certificates (ECerts) and transaction
#  certificates (TCerts).
#  The chainfile (if it exists) contains the certificate chain which
#  should be trusted for this CA, where the 1st in the chain is always the
#  root CA certificate.
#############################################################################
ca:
  # Name of this CA
  name:
  # Key file (default: ca-key.pem)
  keyfile: ca-key.pem
  # Certificate file (default: ca-cert.pem)
  certfile: ca-cert.pem
  # Chain file (default: chain-cert.pem)
  chainfile: ca-chain.pem

#############################################################################
#  The registry section controls how the fabric-ca-server does two things:
#  1) authenticates enrollment requests which contain a username and password
#     (also known as an enrollment ID and secret).
#  2) once authenticated, retrieves the identity's attribute names and
#     values which the fabric-ca-server optionally puts into TCerts
#     which it issues for transacting on the Hyperledger Fabric blockchain.
#     These attributes are useful for making access control decisions in
#     chaincode.
#  There are two main configuration options:
#  1) The fabric-ca-server is the registry.
#     This is true if "ldap.enabled" in the ldap section below is false.
#  2) An LDAP server is the registry, in which case the fabric-ca-server
#     calls the LDAP server to perform these tasks.
#     This is true if "ldap.enabled" in the ldap section below is true,
#     which means this "registry" section is ignored.
#############################################################################
registry:
  # Maximum number of times a password/secret can be reused for enrollment
  # (default: -1, which means there is no limit)
  maxenrollments: -1

  # Contains identity information which is used when LDAP is disabled
  identities:
     - name: <<<ADMIN>>>
       pass: <<<ADMINPW>>>
       type: client
       affiliation: ""
       maxenrollments: -1
       attrs:
          hf.Registrar.Roles: "client,user,peer,validator,auditor"
          hf.Registrar.DelegateRoles: "client,user,validator,auditor"
          hf.Revoker: true
          hf.IntermediateCA: true

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
  type: sqlite3
  datasource: fabric-ca-server.db
  tls:
      enabled: false
      certfiles:
        - db-server-cert.pem
      client:
        certfile: db-client-cert.pem
        keyfile: db-client-key.pem

#############################################################################
#  LDAP section
#  If LDAP is enabled, the fabric-ca-server calls LDAP to:
#  1) authenticate enrollment ID and secret (i.e. username and password)
#     for enrollment requests;
#  2) To retrieve identity attributes
#############################################################################
ldap:
   # Enables or disables the LDAP client (default: false)
   # If this is set to true, the "registry" section is ignored.
   enabled: false
   # The URL of the LDAP server
   url: ldap://<adminDN>:<adminPassword>@<host>:<port>/<base>
   tls:
      certfiles:
        - ldap-server-cert.pem
      client:
         certfile: ldap-client-cert.pem
         keyfile: ldap-client-key.pem

#############################################################################
#  Affiliation section
#############################################################################
affiliations:
   org1:
      - department1
      - department2
   org2:
      - department1

#############################################################################
#  Signing section
#
#  The "default" subsection is used to sign enrollment certificates;
#  the default expiration ("expiry" field) is "8760h", which is 1 year in hours.
#
#  The "ca" profile subsection is used to sign intermediate CA certificates;
#  the default expiration ("expiry" field) is "43800h" which is 5 years in hours.
#  Note that "isca" is true, meaning that it issues a CA certificate.
#  A maxpathlen of 0 means that the intermediate CA cannot issue other
#  intermediate CA certificates, though it can still issue end entity certificates.
#  (See RFC 5280, section 4.2.1.9)
#
#  The "tls" profile subsection is used to sign TLS certificate requests;
#  the default expiration ("expiry" field) is "8760h", which is 1 year in hours.
#############################################################################
signing:
    default:
      usage:
        - digital signature
      expiry: 8760h
    profiles:
      ca:
         usage:
           - cert sign
         expiry: 43800h
         caconstraint:
           isca: true
           maxpathlen: 0
      tls:
         usage:
            - signing
            - key encipherment
            - server auth
            - client auth
            - key agreement
         expiry: 8760h

###########################################################################
#  Certificate Signing Request (CSR) section.
#  This controls the creation of the root CA certificate.
#  The expiration for the root CA certificate is configured with the
#  "ca.expiry" field below, whose default value is "131400h" which is
#  15 years in hours.
#  The pathlength field is used to limit CA certificate hierarchy as described
#  in section 4.2.1.9 of RFC 5280.
#  Examples:
#  1) No pathlength value means no limit is requested.
#  2) pathlength == 1 means a limit of 1 is requested which is the default for
#     a root CA.  This means the root CA can issue intermediate CA certificates,
#     but these intermediate CAs may not in turn issue other CA certificates
#     though they can still issue end entity certificates.
#  3) pathlength == 0 means a limit of 0 is requested;
#     this is the default for an intermediate CA, which means it can not issue
#     CA certificates though it can still issue end entity certificates.
###########################################################################
csr:
   cn: <<<COMMONNAME>>>
   names:
      - C: US
        ST: "North Carolina"
        L:
        O: Hyperledger
        OU: Fabric
   hosts:
     - <<<MYHOST>>>
     - localhost
   ca:
      expiry: 131400h
      pathlength: <<<PATHLENGTH>>>

#############################################################################
# BCCSP (BlockChain Crypto Service Provider) section is used to select which
# crypto library implementation to use
#############################################################################
bccsp:
    default: SW
    sw:
        hash: SHA2
        security: 256
        filekeystore:
            # The directory used for the software file-based keystore
            keystore: msp/keystore

#############################################################################
# Multi CA section
#
# Each Fabric CA server contains one CA by default.  This section is used
# to configure multiple CAs in a single server.
#
# 1) --cacount <number-of-CAs>
# Automatically generate <number-of-CAs> non-default CAs.  The names of these
# additional CAs are "ca1", "ca2", ... "caN", where "N" is <number-of-CAs>
# This is particularly useful in a development environment to quickly set up
# multiple CAs.
#
# 2) --cafiles <CA-config-files>
# For each CA config file in the list, generate a separate signing CA.  Each CA
# config file in this list MAY contain all of the same elements as are found in
# the server config file except port, debug, and tls sections.
#
# Examples:
# fabric-ca-server start -b admin:adminpw --cacount 2
#
# fabric-ca-server start -b admin:adminpw --cafiles ca/ca1/fabric-ca-server-config.yaml
# --cafiles ca/ca2/fabric-ca-server-config.yaml
#
#############################################################################

cacount:

cafiles:

#############################################################################
# Intermediate CA section
#
# The relationship between servers and CAs is as follows:
#   1) A single server process may contain or function as one or more CAs.
#      This is configured by the "Multi CA section" above.
#   2) Each CA is either a root CA or an intermediate CA.
#   3) Each intermediate CA has a parent CA which is either a root CA or another intermediate CA.
#
# This section pertains to configuration of #2 and #3.
# If the "intermediate.parentserver.url" property is set,
# then this is an intermediate CA with the specified parent
# CA.
#
# parentserver section
#    url - The URL of the parent server
#    caname - Name of the CA to enroll within the server
#
# enrollment section used to enroll intermediate CA with parent CA
#    profile - Name of the signing profile to use in issuing the certificate
#    label - Label to use in HSM operations
#
# tls section for secure socket connection
#   certfiles - PEM-encoded list of trusted root certificate files
#   client:
#     certfile - PEM-encoded certificate file for when client authentication
#     is enabled on server
#     keyfile - PEM-encoded key file for when client authentication
#     is enabled on server
#############################################################################
intermediate:
  parentserver:
    url:
    caname:

  enrollment:
    hosts:
    profile:
    label:

  tls:
    certfiles:
    client:
      certfile:
      keyfile:
`
)

var (
	extraArgsError = "Unrecognized arguments found: %v\n\n%s"
)

// Initialize config
func (s *ServerCmd) configInit() (err error) {
	if !s.configRequired() {
		return nil
	}

	s.cfgFileName, s.homeDirectory, err = util.ValidateAndReturnAbsConf(s.cfgFileName, s.homeDirectory, cmdName)
	if err != nil {
		return err
	}

	log.Debugf("Home directory: %s", s.homeDirectory)

	// If the config file doesn't exist, create a default one
	if !util.FileExists(s.cfgFileName) {
		err = s.createDefaultConfigFile()
		if err != nil {
			return errors.WithMessage(err, "Failed to create default configuration file")
		}
		log.Infof("Created default configuration file at %s", s.cfgFileName)
	} else {
		log.Infof("Configuration file location: %s", s.cfgFileName)
	}

	// Read the config
	s.myViper.AutomaticEnv() // read in environment variables that match
	err = lib.UnmarshalConfig(s.cfg, s.myViper, s.cfgFileName, true, true)
	if err != nil {
		return err
	}

	// The pathlength field controls how deep the CA hierarchy when requesting
	// certificates. If it is explicitly set to 0, set the PathLenZero field to
	// true as CFSSL expects.
	pl := "csr.ca.pathlength"
	if s.myViper.IsSet(pl) && s.myViper.GetInt(pl) == 0 {
		s.cfg.CAcfg.CSR.CA.PathLenZero = true
	}
	// The maxpathlen field controls how deep the CA hierarchy when issuing
	// a CA certificate. If it is explicitly set to 0, set the PathLenZero
	// field to true as CFSSL expects.
	pl = "signing.profiles.ca.caconstraint.maxpathlen"
	if s.myViper.IsSet(pl) && s.myViper.GetInt(pl) == 0 {
		s.cfg.CAcfg.Signing.Profiles["ca"].CAConstraint.MaxPathLenZero = true
	}

	return nil
}

func (s *ServerCmd) createDefaultConfigFile() error {
	var user, pass string
	// If LDAP is enabled, authentication of enrollment requests are performed
	// by using LDAP authentication; therefore, no bootstrap username and password
	// are required.
	ldapEnabled := s.myViper.GetBool("ldap.enabled")
	if !ldapEnabled {
		// When LDAP is disabled, the fabric-ca-server functions as its own
		// identity registry; therefore, we require that the default configuration
		// file have a bootstrap username and password that is used to enroll a
		// bootstrap administrator.  Other identities can be dynamically registered.
		// Create the default config, but only if they provided this bootstrap
		// username and password.
		up := s.myViper.GetString("boot")
		if up == "" {
			return errors.New("The '-b user:pass' option is required")
		}
		ups := strings.Split(up, ":")
		if len(ups) < 2 {
			return errors.Errorf("The value '%s' on the command line is missing a colon separator", up)
		}
		if len(ups) > 2 {
			ups = []string{ups[0], strings.Join(ups[1:], ":")}
		}
		user = ups[0]
		pass = ups[1]
		if len(user) >= 1024 {
			return errors.Errorf("The identity name must be less than 1024 characters: '%s'", user)
		}
		if len(pass) == 0 {
			return errors.New("An empty password in the '-b user:pass' option is not permitted")
		}
	}

	var myhost string
	var err error
	myhost, err = os.Hostname()
	if err != nil {
		return err
	}

	// Do string subtitution to get the default config
	cfg := strings.Replace(defaultCfgTemplate, "<<<ADMIN>>>", user, 1)
	cfg = strings.Replace(cfg, "<<<ADMINPW>>>", pass, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)
	purl := s.myViper.GetString("intermediate.parentserver.url")
	log.Debugf("parent server URL: '%s'", purl)
	if purl == "" {
		// This is a root CA
		cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", "fabric-ca-server", 1)
		cfg = strings.Replace(cfg, "<<<PATHLENGTH>>>", "1", 1)
	} else {
		// This is an intermediate CA
		cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", "", 1)
		cfg = strings.Replace(cfg, "<<<PATHLENGTH>>>", "0", 1)
	}

	// Now write the file
	cfgDir := filepath.Dir(s.cfgFileName)
	err = os.MkdirAll(cfgDir, 0755)
	if err != nil {
		return err
	}

	// Now write the file
	return ioutil.WriteFile(s.cfgFileName, []byte(cfg), 0644)
}
