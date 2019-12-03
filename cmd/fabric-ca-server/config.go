/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	calog "github.com/hyperledger/fabric-ca/lib/common/log"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
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
#      b) --ca.keyfile ../mykey.pem
#         To set the "keyfile" element in the "ca" section below;
#         note the '.' separator character.
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

# Version of config file
version: <<<VERSION>>>

# Server's listening port (default: 7054)
port: 7054

# Cross-Origin Resource Sharing (CORS)
cors:
    enabled: false
    origins:
      - "*"

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
  certfile:
  keyfile:
  clientauth:
    type: noclientcert
    certfiles:

#############################################################################
#  The CA section contains information related to the Certificate Authority
#  including the name of the CA, which should be unique for all members
#  of a blockchain network.  It also includes the key and certificate files
#  used when issuing enrollment certificates (ECerts).
#  The chainfile (if it exists) contains the certificate chain which
#  should be trusted for this CA, where the 1st in the chain is always the
#  root CA certificate.
#############################################################################
ca:
  # Name of this CA
  name:
  # Key file (is only used to import a private key into BCCSP)
  keyfile:
  # Certificate file (default: ca-cert.pem)
  certfile:
  # Chain file
  chainfile:

#############################################################################
#  The gencrl REST endpoint is used to generate a CRL that contains revoked
#  certificates. This section contains configuration options that are used
#  during gencrl request processing.
#############################################################################
crl:
  # Specifies expiration for the generated CRL. The number of hours
  # specified by this property is added to the UTC time, the resulting time
  # is used to set the 'Next Update' date of the CRL.
  expiry: 24h

#############################################################################
#  The registry section controls how the fabric-ca-server does two things:
#  1) authenticates enrollment requests which contain a username and password
#     (also known as an enrollment ID and secret).
#  2) once authenticated, retrieves the identity's attribute names and values.
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
       attrs:
          hf.Registrar.Roles: "*"
          hf.Registrar.DelegateRoles: "*"
          hf.Revoker: true
          hf.IntermediateCA: true
          hf.GenCRL: true
          hf.Registrar.Attributes: "*"
          hf.AffiliationMgr: true

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
      client:
        certfile:
        keyfile:

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
   # TLS configuration for the client connection to the LDAP server
   tls:
      certfiles:
      client:
         certfile:
         keyfile:
   # Attribute related configuration for mapping from LDAP entries to Fabric CA attributes
   attribute:
      # 'names' is an array of strings containing the LDAP attribute names which are
      # requested from the LDAP server for an LDAP identity's entry
      names: ['uid','member']
      # The 'converters' section is used to convert an LDAP entry to the value of
      # a fabric CA attribute.
      # For example, the following converts an LDAP 'uid' attribute
      # whose value begins with 'revoker' to a fabric CA attribute
      # named "hf.Revoker" with a value of "true" (because the boolean expression
      # evaluates to true).
      #    converters:
      #       - name: hf.Revoker
      #         value: attr("uid") =~ "revoker*"
      converters:
         - name:
           value:
      # The 'maps' section contains named maps which may be referenced by the 'map'
      # function in the 'converters' section to map LDAP responses to arbitrary values.
      # For example, assume a user has an LDAP attribute named 'member' which has multiple
      # values which are each a distinguished name (i.e. a DN). For simplicity, assume the
      # values of the 'member' attribute are 'dn1', 'dn2', and 'dn3'.
      # Further assume the following configuration.
      #    converters:
      #       - name: hf.Registrar.Roles
      #         value: map(attr("member"),"groups")
      #    maps:
      #       groups:
      #          - name: dn1
      #            value: peer
      #          - name: dn2
      #            value: client
      # The value of the user's 'hf.Registrar.Roles' attribute is then computed to be
      # "peer,client,dn3".  This is because the value of 'attr("member")' is
      # "dn1,dn2,dn3", and the call to 'map' with a 2nd argument of
      # "group" replaces "dn1" with "peer" and "dn2" with "client".
      maps:
         groups:
            - name:
              value:

#############################################################################
# Affiliations section. Fabric CA server can be bootstrapped with the
# affiliations specified in this section. Affiliations are specified as maps.
# For example:
#   businessunit1:
#     department1:
#       - team1
#   businessunit2:
#     - department2
#     - department3
#
# Affiliations are hierarchical in nature. In the above example,
# department1 (used as businessunit1.department1) is the child of businessunit1.
# team1 (used as businessunit1.department1.team1) is the child of department1.
# department2 (used as businessunit2.department2) and department3 (businessunit2.department3)
# are children of businessunit2.
# Note: Affiliations are case sensitive except for the non-leaf affiliations
# (like businessunit1, department1, businessunit2) that are specified in the configuration file,
# which are always stored in lower case.
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
           - crl sign
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
   keyrequest:
     algo: ecdsa
     size: 256
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

###########################################################################
# Each CA can issue both X509 enrollment certificate as well as Idemix
# Credential. This section specifies configuration for the issuer component
# that is responsible for issuing Idemix credentials.
###########################################################################
idemix:
  # Specifies pool size for revocation handles. A revocation handle is an unique identifier of an
  # Idemix credential. The issuer will create a pool revocation handles of this specified size. When
  # a credential is requested, issuer will get handle from the pool and assign it to the credential.
  # Issuer will repopulate the pool with new handles when the last handle in the pool is used.
  # A revocation handle and credential revocation information (CRI) are used to create non revocation proof
  # by the prover to prove to the verifier that her credential is not revoked.
  rhpoolsize: 1000

  # The Idemix credential issuance is a two step process. First step is to  get a nonce from the issuer
  # and second step is send credential request that is constructed using the nonce to the isuser to
  # request a credential. This configuration property specifies expiration for the nonces. By default is
  # nonces expire after 15 seconds. The value is expressed in the time.Duration format (see https://golang.org/pkg/time/#ParseDuration).
  nonceexpiration: 15s

  # Specifies interval at which expired nonces are removed from datastore. Default value is 15 minutes.
  #  The value is expressed in the time.Duration format (see https://golang.org/pkg/time/#ParseDuration)
  noncesweepinterval: 15m

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
# multiple CAs. Note that, this config option is not applicable to intermediate CA server
# i.e., Fabric CA server that is started with intermediate.parentserver.url config
# option (-u command line option)
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

#############################################################################
# CA configuration section
#
# Configure the number of incorrect password attempts are allowed for
# identities. By default, the value of 'passwordattempts' is 10, which
# means that 10 incorrect password attempts can be made before an identity get
# locked out.
#############################################################################
cfg:
  identities:
    passwordattempts: 10

###############################################################################
#
#    Operations section
#
###############################################################################
operations:
    # host and port for the operations server
    listenAddress: 127.0.0.1:9443

    # TLS configuration for the operations endpoint
    tls:
        # TLS enabled
        enabled: false

        # path to PEM encoded server certificate for the operations server
        cert:
            file:

        # path to PEM encoded server key for the operations server
        key:
            file:

        # require client certificate authentication to access all resources
        clientAuthRequired: false

        # paths to PEM encoded ca certificates to trust for client authentication
        clientRootCAs:
            files: []

###############################################################################
#
#    Metrics section
#
###############################################################################
metrics:
    # statsd, prometheus, or disabled
    provider: disabled

    # statsd configuration
    statsd:
        # network type: tcp or udp
        network: udp

        # statsd server address
        address: 127.0.0.1:8125

        # the interval at which locally cached counters and gauges are pushsed
        # to statsd; timings are pushed immediately
        writeInterval: 10s

        # prefix is prepended to all emitted statsd merics
        prefix: server
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

	s.myViper.AutomaticEnv() // read in environment variables that match
	logLevel := s.myViper.GetString("loglevel")
	debug := s.myViper.GetBool("debug")
	calog.SetLogLevel(logLevel, debug)

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
	err = lib.UnmarshalConfig(s.cfg, s.myViper, s.cfgFileName, true)
	if err != nil {
		return err
	}

	// Read operations tls files
	if s.myViper.GetBool("operations.tls.enabled") {
		cf := s.myViper.GetString("operations.tls.cert.file")
		if !filepath.IsAbs(cf) {
			cf = filepath.Join(s.homeDirectory, cf)
		}
		if util.FileExists(cf) {
			s.cfg.Operations.TLS.CertFile = cf
		} else {
			return errors.Errorf("failed to read certificate file: %s", cf)
		}
		kf := s.myViper.GetString("operations.tls.key.file")
		if !filepath.IsAbs(kf) {
			kf = filepath.Join(s.homeDirectory, kf)
		}
		if util.FileExists(kf) {
			s.cfg.Operations.TLS.KeyFile = kf
		} else {
			return errors.Errorf("failed to read key file: %s", kf)
		}
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
	cfg := strings.Replace(defaultCfgTemplate, "<<<VERSION>>>", metadata.Version, 1)
	cfg = strings.Replace(cfg, "<<<ADMIN>>>", user, 1)
	cfg = strings.Replace(cfg, "<<<ADMINPW>>>", pass, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)
	purl := s.myViper.GetString("intermediate.parentserver.url")
	log.Debugf("parent server URL: '%s'", util.GetMaskedURL(purl))
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
