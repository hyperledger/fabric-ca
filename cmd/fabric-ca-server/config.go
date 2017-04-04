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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"
)

const (
	longName     = "Hyperledger Fabric Certificate Authority Server"
	shortName    = "fabric-ca server"
	cmdName      = "fabric-ca-server"
	envVarPrefix = "FABRIC_CA_SERVER"
	homeEnvVar   = "FABRIC_CA_SERVER_HOME"
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
#   All filename elements below end with the word "file".
#   For example, see "certfile" and "keyfile" in the "ca" section.
#   The value of each filename element can be a simple filename, a
#   relative path, or an absolute path.  If the value is not an
#   absolute path, it is interpretted as being relative to the location
#   of this configuration file.
#
#############################################################################

# Server's listening port (default: 7054)
port: 7054

# Enables debug logging (default: false)
debug: false

#############################################################################
#  TLS section for the server's listening port
#
#  The following types are supported for client authentication: NoClientCert,
#  RequestClientCert, RequireAnyClientCert, VerfiyClientCertIfGiven,
#  and RequireAndVerifyClientCert.
#
#  Certfiles is a list of root certificate authorities that the server uses
#  when verifying client certificates.
#############################################################################
tls:
  # Enable TLS (default: false)
  enabled: false
  # TLS for the server's listening port
  certfile: ca-cert.pem
  keyfile: ca-key.pem
  clientauth:
    type: noclientcert
    certfiles: 			# Comma Separated list of root certificate files (e.g. root.pem, root2.pem)

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
  name: <<<CANAME>>>
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
#  1) The fabric-ca-server is the registry
#  2) An LDAP server is the registry, in which case the fabric-ca-server
#     calls the LDAP server to perform these tasks.
#############################################################################
registry:
  # Maximum number of times a password/secret can be reused for enrollment
  # (default: 0, which means there is no limit)
  maxEnrollments: 0

  # Contains user information which is used when LDAP is disabled
  identities:
     - name: <<<ADMIN>>>
       pass: <<<ADMINPW>>>
       type: client
       affiliation: ""
       attrs:
          hf.Registrar.Roles: "client,user,peer,validator,auditor,ca"
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
   enabled: false
   # The URL of the LDAP server
   url: ldap://<adminDN>:<adminPassword>@<host>:<port>/<base>
   tls:
      certfiles: ldap-server-cert.pem				# Comma Separated (e.g. root.pem, root2.pem)
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
#############################################################################
signing:
    profiles:
      ca:
         usage:
           - cert sign
         expiry: 8000h
         caconstraint:
           isca: true
    default:
      usage:
        - cert sign
      expiry: 8000h

###########################################################################
#  Certificate Signing Request section for generating the CA certificate
###########################################################################
csr:
   cn: fabric-ca-server
   names:
      - C: US
        ST: "North Carolina"
        L:
        O: Hyperledger
        OU: Fabric
   hosts:
     - <<<MYHOST>>>
   ca:
      pathlen:
      pathlenzero:
      expiry:

#############################################################################
#  Crypto section configures the crypto primitives used for all
#############################################################################
crypto:
  software:
     hash_family: SHA2
     security_level: 256
     ephemeral: false
     key_store_dir: keys
`
)

var (
	// cfgFileName is the name of the config file
	cfgFileName string
	// serverCfg is the server's config
	serverCfg *lib.ServerConfig
)

// Initialize config
func configInit() (err error) {

	// Make the config file name absolute
	if !filepath.IsAbs(cfgFileName) {
		cfgFileName, err = filepath.Abs(cfgFileName)
		if err != nil {
			return fmt.Errorf("Failed to get full path of config file: %s", err)
		}
	}

	// If the config file doesn't exist, create a default one
	if !util.FileExists(cfgFileName) {
		err = createDefaultConfigFile()
		if err != nil {
			return fmt.Errorf("Failed to create default configuration file: %s", err)
		}
		log.Infof("Created default configuration file at %s", cfgFileName)
	} else {
		log.Infof("Configuration file location: %s", cfgFileName)
	}

	// Read the config
	viper.SetConfigFile(cfgFileName)
	viper.AutomaticEnv() // read in environment variables that match
	err = viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("Failed to read config file: %s", err)
	}

	// Unmarshal the config into 'serverCfg'
	// When viper bug https://github.com/spf13/viper/issues/327 is fixed
	// and vendored, the work around code can be deleted.
	viperIssue327WorkAround := true
	if viperIssue327WorkAround {
		sliceFields := []string{
			"csr.hosts",
			"tls.clientauth.certfiles",
		}
		err = util.ViperUnmarshal(serverCfg, sliceFields)
		if err != nil {
			return fmt.Errorf("Incorrect format in file '%s': %s", cfgFileName, err)
		}
	} else {
		err = viper.Unmarshal(serverCfg)
		if err != nil {
			return fmt.Errorf("Incorrect format in file '%s': %s", cfgFileName, err)
		}
	}

	return nil
}

func createDefaultConfigFile() error {
	// Create a default config, but only if they provided an administrative
	// user ID and password
	up := viper.GetString("boot")
	if up == "" {
		return errors.New("The '-b user:pass' option is required")
	}
	ups := strings.Split(up, ":")
	if len(ups) < 2 {
		return fmt.Errorf("The value '%s' on the command line is missing a colon separator", up)
	}
	if len(ups) > 2 {
		ups = []string{ups[0], strings.Join(ups[1:], ":")}
	}
	user := ups[0]
	pass := ups[1]
	if len(user) >= 1024 {
		return fmt.Errorf("The user name must be less than 1024 characters: '%s'", user)
	}
	if len(pass) == 0 {
		return errors.New("An empty password in the '-b user:pass' option is not permitted")
	}
	// Get hostname
	myhost, err := os.Hostname()
	if err != nil {
		return err
	}
	// Get domain name
	mydomain := strings.Join(strings.Split(myhost, ".")[1:], ".")
	// Do string subtitution to get the default config
	cfg := strings.Replace(defaultCfgTemplate, "<<<ADMIN>>>", user, 1)
	cfg = strings.Replace(cfg, "<<<ADMINPW>>>", pass, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)
	cfg = strings.Replace(cfg, "<<<CANAME>>>", mydomain, 1)
	// Now write the file
	err = os.MkdirAll(filepath.Dir(cfgFileName), 0755)
	if err != nil {
		return err
	}
	// Now write the file
	return ioutil.WriteFile(cfgFileName, []byte(cfg), 0644)
}
