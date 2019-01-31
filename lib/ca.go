/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/config"
	cfcsr "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	cflocalsigner "github.com/cloudflare/cfssl/signer/local"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/lib/common"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	cadb "github.com/hyperledger/fabric-ca/lib/server/db"
	cadbfactory "github.com/hyperledger/fabric-ca/lib/server/db/factory"
	"github.com/hyperledger/fabric-ca/lib/server/db/mysql"
	"github.com/hyperledger/fabric-ca/lib/server/db/postgres"
	"github.com/hyperledger/fabric-ca/lib/server/db/sqlite"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	idemix "github.com/hyperledger/fabric-ca/lib/server/idemix"
	"github.com/hyperledger/fabric-ca/lib/server/ldap"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/lib/tcert"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/attrmgr"
	"github.com/pkg/errors"
)

const (
	defaultDatabaseType = "sqlite3"
	// CAChainParentFirstEnvVar is the name of the environment variable that needs to be set
	// for server to return CA chain in parent-first order
	CAChainParentFirstEnvVar = "CA_CHAIN_PARENT_FIRST"
)

var (
	// Default root CA certificate expiration is 15 years (in hours).
	defaultRootCACertificateExpiration = "131400h"
	// Default intermediate CA certificate expiration is 5 years (in hours).
	defaultIntermediateCACertificateExpiration = parseDuration("43800h")
	// Default issued certificate expiration is 1 year (in hours).
	defaultIssuedCertificateExpiration = parseDuration("8760h")
)

// CA represents a certificate authority which signs, issues and revokes certificates
type CA struct {
	// The home directory for the CA
	HomeDir string
	// The CA's configuration
	Config *CAConfig
	// The file path of the config file
	ConfigFilePath string
	// The database handle used to store certificates and optionally
	// the user registry information, unless LDAP it enabled for the
	// user registry function.
	db db.FabricCADB
	// The crypto service provider (BCCSP)
	csp bccsp.BCCSP
	// The certificate DB accessor
	certDBAccessor *CertDBAccessor
	// The user registry
	registry user.Registry
	// The signer used for enrollment
	enrollSigner signer.Signer
	// Idemix issuer
	issuer idemix.Issuer
	// The options to use in verifying a signature in token-based authentication
	verifyOptions *x509.VerifyOptions
	// The attribute manager
	attrMgr *attrmgr.Mgr
	// The tcert manager for this CA
	tcertMgr *tcert.Mgr
	// The key tree
	keyTree *tcert.KeyTree
	// The server hosting this CA
	server *Server
	// DB levels
	levels *dbutil.Levels
	// CA mutex
	mutex sync.Mutex
}

const (
	certificateError = "Invalid certificate in file"
)

// newCA creates a new CA with the specified
// home directory, parent server URL, and config
func newCA(caFile string, config *CAConfig, server *Server, renew bool) (*CA, error) {
	ca := new(CA)
	ca.ConfigFilePath = caFile
	err := initCA(ca, filepath.Dir(caFile), config, server, renew)
	if err != nil {
		err2 := ca.closeDB()
		if err2 != nil {
			log.Errorf("Close DB failed: %s", err2)
		}
		return nil, err
	}
	return ca, nil
}

// initCA will initialize the passed in pointer to a CA struct
func initCA(ca *CA, homeDir string, config *CAConfig, server *Server, renew bool) error {
	ca.HomeDir = homeDir
	ca.Config = config
	ca.server = server

	err := ca.init(renew)
	if err != nil {
		return err
	}
	log.Debug("Initializing Idemix issuer...")
	ca.issuer = idemix.NewIssuer(ca.Config.CA.Name, ca.HomeDir,
		&ca.Config.Idemix, ca.csp, idemix.NewLib())
	err = ca.issuer.Init(renew, ca.db, ca.levels)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to initialize Idemix issuer for CA '%s'", err.Error()))
	}
	return nil
}

// Init initializes an instance of a CA
func (ca *CA) init(renew bool) (err error) {
	log.Debugf("Init CA with home %s and config %+v", ca.HomeDir, *ca.Config)

	// Initialize the config, setting defaults, etc
	err = ca.initConfig()
	if err != nil {
		return err
	}

	// Initialize the crypto layer (BCCSP) for this CA
	ca.csp, err = util.InitBCCSP(&ca.Config.CSP, "", ca.HomeDir)
	if err != nil {
		return err
	}

	// Initialize key materials
	err = ca.initKeyMaterial(renew)
	if err != nil {
		return err
	}

	// Initialize the database
	err = ca.initDB()
	if err != nil {
		log.Error("Error occurred initializing database: ", err)
		// Return if a server configuration error encountered (e.g. Invalid max enrollment for a bootstrap user)
		if caerrors.IsFatalError(err) {
			return err
		}
	}
	// Initialize the enrollment signer
	err = ca.initEnrollmentSigner()
	if err != nil {
		return err
	}
	// Create the attribute manager
	ca.attrMgr = attrmgr.New()
	// Initialize TCert handling
	keyfile := ca.Config.CA.Keyfile
	certfile := ca.Config.CA.Certfile
	ca.tcertMgr, err = tcert.LoadMgr(keyfile, certfile, ca.csp)
	if err != nil {
		return err
	}
	// FIXME: The root prekey must be stored persistently in DB and retrieved here if not found
	rootKey, err := genRootKey(ca.csp)
	if err != nil {
		return err
	}
	ca.keyTree = tcert.NewKeyTree(ca.csp, rootKey)
	log.Debug("CA initialization successful")
	// Successful initialization
	return nil
}

// Initialize the CA's key material
func (ca *CA) initKeyMaterial(renew bool) error {
	log.Debug("Initialize key material")

	// Make the path names absolute in the config
	err := ca.makeFileNamesAbsolute()
	if err != nil {
		return err
	}

	keyFile := ca.Config.CA.Keyfile
	certFile := ca.Config.CA.Certfile

	// If we aren't renewing and the key and cert files exist, do nothing
	if !renew {
		// If they both exist, the CA was already initialized
		keyFileExists := util.FileExists(keyFile)
		certFileExists := util.FileExists(certFile)
		if keyFileExists && certFileExists {
			log.Info("The CA key and certificate files already exist")
			log.Infof("Key file location: %s", keyFile)
			log.Infof("Certificate file location: %s", certFile)
			err = ca.validateCertAndKey(certFile, keyFile)
			if err != nil {
				return errors.WithMessage(err, "Validation of certificate and key failed")
			}
			// Load CN from existing enrollment information and set CSR accordingly
			// CN needs to be set, having a multi CA setup requires a unique CN and can't
			// be left blank
			ca.Config.CSR.CN, err = ca.loadCNFromEnrollmentInfo(certFile)
			if err != nil {
				return err
			}
			return nil
		}

		// If key file does not exist but certFile does, key file is probably
		// stored by BCCSP, so check for that now.
		if certFileExists {
			_, _, _, err = util.GetSignerFromCertFile(certFile, ca.csp)
			if err != nil {
				return errors.WithMessage(err, fmt.Sprintf("Failed to find private key for certificate in '%s'", certFile))
			}
			// Yes, it is stored by BCCSP
			log.Info("The CA key and certificate already exist")
			log.Infof("The key is stored by BCCSP provider '%s'", ca.Config.CSP.ProviderName)
			log.Infof("The certificate is at: %s", certFile)
			// Load CN from existing enrollment information and set CSR accordingly
			// CN needs to be set, having a multi CA setup requires a unique CN and can't
			// be left blank
			ca.Config.CSR.CN, err = ca.loadCNFromEnrollmentInfo(certFile)
			if err != nil {
				return errors.WithMessage(err, fmt.Sprintf("Failed to get CN for certificate in '%s'", certFile))
			}
			return nil
		}
		log.Warning(caerrors.NewServerError(caerrors.ErrCACertFileNotFound, "The specified CA certificate file %s does not exist", certFile))
	}

	// Get the CA cert
	cert, err := ca.getCACert()
	if err != nil {
		return err
	}
	// Store the certificate to file
	err = writeFile(certFile, cert, 0644)
	if err != nil {
		return errors.Wrap(err, "Failed to store certificate")
	}
	log.Infof("The CA key and certificate were generated for CA %s", ca.Config.CA.Name)
	log.Infof("The key was stored by BCCSP provider '%s'", ca.Config.CSP.ProviderName)
	log.Infof("The certificate is at: %s", certFile)

	return nil
}

// Get the CA certificate for this CA
func (ca *CA) getCACert() (cert []byte, err error) {
	if ca.Config.Intermediate.ParentServer.URL != "" {
		// This is an intermediate CA, so call the parent fabric-ca-server
		// to get the cert
		log.Debugf("Getting CA cert; parent server URL is %s", util.GetMaskedURL(ca.Config.Intermediate.ParentServer.URL))
		clientCfg := ca.Config.Client
		if clientCfg == nil {
			clientCfg = &ClientConfig{}
		}
		// Copy over the intermediate configuration into client configuration
		clientCfg.TLS = ca.Config.Intermediate.TLS
		clientCfg.Enrollment = ca.Config.Intermediate.Enrollment
		clientCfg.CAName = ca.Config.Intermediate.ParentServer.CAName
		clientCfg.CSP = ca.Config.CSP
		clientCfg.CSR = ca.Config.CSR
		clientCfg.CSP = ca.Config.CSP
		if ca.Config.CSR.CN != "" {
			return nil, errors.Errorf("CN '%s' cannot be specified for an intermediate CA. Remove CN from CSR section for enrollment of intermediate CA to be successful", ca.Config.CSR.CN)
		}
		if clientCfg.Enrollment.Profile == "" {
			clientCfg.Enrollment.Profile = "ca"
		}
		if clientCfg.Enrollment.CSR == nil {
			clientCfg.Enrollment.CSR = &api.CSRInfo{}
		}
		if clientCfg.Enrollment.CSR.CA == nil {
			clientCfg.Enrollment.CSR.CA = &cfcsr.CAConfig{PathLength: 0, PathLenZero: true}
		}
		log.Debugf("Intermediate enrollment request: %+v, CSR: %+v, CA: %+v",
			clientCfg.Enrollment, clientCfg.Enrollment.CSR, clientCfg.Enrollment.CSR.CA)
		var resp *EnrollmentResponse
		resp, err = clientCfg.Enroll(ca.Config.Intermediate.ParentServer.URL, ca.HomeDir)
		if err != nil {
			return nil, err
		}
		// Set the CN for an intermediate server to be the ID used to enroll with root CA
		ca.Config.CSR.CN = resp.Identity.GetName()
		ecert := resp.Identity.GetECert()
		if ecert == nil {
			return nil, errors.New("No enrollment certificate returned by parent server")
		}
		cert = ecert.Cert()
		// Store the chain file as the concatenation of the parent's chain plus the cert.
		chainPath := ca.Config.CA.Chainfile
		chain, err := ca.concatChain(resp.CAInfo.CAChain, cert)
		if err != nil {
			return nil, err
		}
		err = os.MkdirAll(path.Dir(chainPath), 0755)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create intermediate chain file directory")
		}
		err = util.WriteFile(chainPath, chain, 0644)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to create intermediate chain file")
		}
		log.Debugf("Stored intermediate certificate chain at %s", chainPath)
	} else {
		// This is a root CA, so create a CSR (Certificate Signing Request)
		if ca.Config.CSR.CN == "" {
			ca.Config.CSR.CN = "fabric-ca-server"
		}
		csr := &ca.Config.CSR
		if csr.CA == nil {
			csr.CA = &cfcsr.CAConfig{}
		}
		if csr.CA.Expiry == "" {
			csr.CA.Expiry = defaultRootCACertificateExpiration
		}

		if (csr.KeyRequest == nil) || (csr.KeyRequest.Algo == "" && csr.KeyRequest.Size == 0) {
			csr.KeyRequest = GetKeyRequest(ca.Config)
		}
		req := cfcsr.CertificateRequest{
			CN:           csr.CN,
			Names:        csr.Names,
			Hosts:        csr.Hosts,
			KeyRequest:   &cfcsr.BasicKeyRequest{A: csr.KeyRequest.Algo, S: csr.KeyRequest.Size},
			CA:           csr.CA,
			SerialNumber: csr.SerialNumber,
		}
		log.Debugf("Root CA certificate request: %+v", req)
		// Generate the key/signer
		_, cspSigner, err := util.BCCSPKeyRequestGenerate(&req, ca.csp)
		if err != nil {
			return nil, err
		}
		// Call CFSSL to initialize the CA
		cert, _, err = initca.NewFromSigner(&req, cspSigner)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to create new CA certificate")
		}
	}
	return cert, nil
}

// Return a certificate chain which is the concatenation of chain and cert
func (ca *CA) concatChain(chain []byte, cert []byte) ([]byte, error) {
	result := make([]byte, len(chain)+len(cert))
	parentFirst, ok := os.LookupEnv(CAChainParentFirstEnvVar)
	parentFirstBool := false
	// If CA_CHAIN_PARENT_FIRST env variable is set then get the boolean
	// value
	if ok {
		var err error
		parentFirstBool, err = strconv.ParseBool(parentFirst)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse the environment variable '%s'", CAChainParentFirstEnvVar)
		}
	}
	if parentFirstBool {
		copy(result[:len(chain)], chain)
		copy(result[len(chain):], cert)
	} else {
		copy(result[:len(cert)], cert)
		copy(result[len(cert):], chain)
	}
	return result, nil
}

// Get the certificate chain for the CA
func (ca *CA) getCAChain() (chain []byte, err error) {
	if ca.Config == nil {
		return nil, errors.New("The server has no configuration")
	}
	certAuth := &ca.Config.CA
	// If the chain file exists, we always return the chain from here
	if util.FileExists(certAuth.Chainfile) {
		return util.ReadFile(certAuth.Chainfile)
	}
	// Otherwise, if this is a root CA, we always return the contents of the CACertfile
	if ca.Config.Intermediate.ParentServer.URL == "" {
		return util.ReadFile(certAuth.Certfile)
	}
	// If this is an intermediate CA but the ca.Chainfile doesn't exist,
	// it is an error.  It should have been created during intermediate CA enrollment.
	return nil, errors.Errorf("Chain file does not exist at %s", certAuth.Chainfile)
}

// Initialize the configuration for the CA setting any defaults and making filenames absolute
func (ca *CA) initConfig() (err error) {
	// Init home directory if not set
	if ca.HomeDir == "" {
		ca.HomeDir, err = os.Getwd()
		if err != nil {
			return errors.Wrap(err, "Failed to initialize CA's home directory")
		}
	}
	log.Debugf("CA Home Directory: %s", ca.HomeDir)
	// Init config if not set
	if ca.Config == nil {
		ca.Config = new(CAConfig)
		ca.Config.Registry.MaxEnrollments = -1
	}
	// Set config defaults
	cfg := ca.Config
	if cfg.Version == "" {
		cfg.Version = "0"
	}
	if cfg.CA.Certfile == "" {
		cfg.CA.Certfile = "ca-cert.pem"
	}
	if cfg.CA.Keyfile == "" {
		cfg.CA.Keyfile = "ca-key.pem"
	}
	if cfg.CA.Chainfile == "" {
		cfg.CA.Chainfile = "ca-chain.pem"
	}
	if cfg.CSR.CA == nil {
		cfg.CSR.CA = &cfcsr.CAConfig{}
	}
	if cfg.CSR.CA.Expiry == "" {
		cfg.CSR.CA.Expiry = defaultRootCACertificateExpiration
	}
	if cfg.Signing == nil {
		cfg.Signing = &config.Signing{}
	}
	cs := cfg.Signing
	if cs.Profiles == nil {
		cs.Profiles = make(map[string]*config.SigningProfile)
	}
	caProfile := cs.Profiles["ca"]
	initSigningProfile(&caProfile,
		defaultIntermediateCACertificateExpiration,
		true)
	cs.Profiles["ca"] = caProfile
	initSigningProfile(
		&cs.Default,
		defaultIssuedCertificateExpiration,
		false)
	tlsProfile := cs.Profiles["tls"]
	initSigningProfile(&tlsProfile,
		defaultIssuedCertificateExpiration,
		false)
	cs.Profiles["tls"] = tlsProfile
	err = ca.checkConfigLevels()
	if err != nil {
		return err
	}
	// Set log level if debug is true
	if ca.server != nil && ca.server.Config != nil && ca.server.Config.Debug {
		log.Level = log.LevelDebug
	}
	ca.normalizeStringSlices()

	return nil
}

// VerifyCertificate verifies that 'cert' was issued by this CA
// Return nil if successful; otherwise, return an error.
func (ca *CA) VerifyCertificate(cert *x509.Certificate) error {
	opts, err := ca.getVerifyOptions()
	if err != nil {
		return errors.WithMessage(err, "Failed to get verify options")
	}
	_, err = cert.Verify(*opts)
	if err != nil {
		return errors.WithMessage(err, "Failed to verify certificate")
	}
	return nil
}

// Get the options to verify
func (ca *CA) getVerifyOptions() (*x509.VerifyOptions, error) {
	if ca.verifyOptions != nil {
		return ca.verifyOptions, nil
	}
	chain, err := ca.getCAChain()
	if err != nil {
		return nil, err
	}
	var intPool *x509.CertPool
	var rootPool *x509.CertPool

	for len(chain) > 0 {
		var block *pem.Block
		block, chain = pem.Decode(chain)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse CA chain certificate")
		}

		if !cert.IsCA {
			return nil, errors.New("A certificate in the CA chain is not a CA certificate")
		}

		// If authority key id is not present or if it is present and equal to subject key id,
		// then it is a root certificate
		if len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
			if rootPool == nil {
				rootPool = x509.NewCertPool()
			}
			rootPool.AddCert(cert)
		} else {
			if intPool == nil {
				intPool = x509.NewCertPool()
			}
			intPool.AddCert(cert)
		}
	}

	ca.verifyOptions = &x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	return ca.verifyOptions, nil
}

// Initialize the database for the CA
func (ca *CA) initDB() error {
	log.Debug("Initializing DB")

	// If DB is initialized, don't need to proceed further
	if ca.db != nil && ca.db.IsInitialized() {
		return nil
	}

	ca.mutex.Lock()
	defer ca.mutex.Unlock()

	// After obtaining a lock, check again to see if DB got initialized by another process
	if ca.db != nil && ca.db.IsInitialized() {
		return nil
	}

	dbCfg := &ca.Config.DB
	dbError := false
	var err error

	if dbCfg.Type == "" || dbCfg.Type == defaultDatabaseType {

		dbCfg.Type = defaultDatabaseType

		if dbCfg.Datasource == "" {
			dbCfg.Datasource = "fabric-ca-server.db"
		}

		dbCfg.Datasource, err = util.MakeFileAbs(dbCfg.Datasource, ca.HomeDir)
		if err != nil {
			return err
		}
	}

	// Strip out user:pass from datasource for logging
	ds := dbCfg.Datasource
	ds = dbutil.MaskDBCred(ds)

	log.Debugf("Initializing '%s' database at '%s'", dbCfg.Type, ds)
	caDB, err := cadbfactory.New(dbCfg.Type, dbCfg.Datasource, ca.Config.CA.Name, &dbCfg.TLS, ca.csp, ca.server.Operations)
	if err != nil {
		return err
	}
	err = caDB.Connect()
	if err != nil {
		return err
	}
	sqlxdb, err := caDB.Create()
	if err != nil {
		return err
	}

	ca.db = sqlxdb
	// Set the certificate DB accessor
	ca.certDBAccessor = NewCertDBAccessor(ca.db, ca.levels.Certificate)

	// If DB initialization fails and we need to reinitialize DB, need to make sure to set the DB accessor for the signer
	if ca.enrollSigner != nil {
		ca.enrollSigner.SetDBAccessor(ca.certDBAccessor)
	}

	// Initialize user registry to either use DB or LDAP
	err = ca.initUserRegistry()
	if err != nil {
		return err
	}

	err = ca.checkDBLevels()
	if err != nil {
		return err
	}

	// Migrate the database
	curLevels, err := cadb.CurrentDBLevels(ca.db)
	if err != nil {
		return errors.Wrap(err, "Failed to current ca levels")
	}
	migrator, err := getMigrator(ca.db.DriverName(), ca.db.BeginTx(), curLevels, ca.server.levels)
	if err != nil {
		return errors.Wrap(err, "Failed to get migrator")
	}
	err = db.Migrate(migrator, curLevels, ca.server.levels)
	if err != nil {
		return errors.Wrap(err, "Failed to migrate database")
	}

	// If not using LDAP, migrate database if needed to latest version and load the users and affiliations table
	if !ca.Config.LDAP.Enabled {
		err = ca.loadUsersTable()
		if err != nil {
			log.Error(err)
			dbError = true
			if caerrors.IsFatalError(err) {
				return err
			}
		}

		err = ca.loadAffiliationsTable()
		if err != nil {
			log.Error(err)
			dbError = true
		}
	}

	if dbError {
		return errors.Errorf("Failed to initialize %s database at %s ", dbCfg.Type, ds)
	}

	ca.db.SetDBInitialized(true)
	log.Infof("Initialized %s database at %s", dbCfg.Type, ds)

	return nil
}

// Close CA's DB
func (ca *CA) closeDB() error {
	if ca.db != nil {
		err := ca.db.Close()
		ca.db = nil
		if err != nil {
			return errors.Wrapf(err, "Failed to close CA database, where CA home directory is '%s'", ca.HomeDir)
		}
	}
	return nil
}

// Initialize the user registry interface
func (ca *CA) initUserRegistry() error {
	log.Debug("Initializing identity registry")
	var err error
	ldapCfg := &ca.Config.LDAP

	if ldapCfg.Enabled {
		// Use LDAP for the user registry
		ca.registry, err = ldap.NewClient(ldapCfg, ca.server.csp)
		log.Debugf("Initialized LDAP identity registry; err=%s", err)
		if err == nil {
			log.Info("Successfully initialized LDAP client")
		} else {
			log.Warningf("Failed to initialize LDAP client; err=%s", err)
		}
		return err
	}

	// Use the DB for the user registry
	ca.registry = NewDBAccessor(ca.db)
	log.Debug("Initialized DB identity registry")
	return nil
}

// Initialize the enrollment signer
func (ca *CA) initEnrollmentSigner() (err error) {
	log.Debug("Initializing enrollment signer")
	c := ca.Config

	// If there is a config, use its signing policy. Otherwise create a default policy.
	var policy *config.Signing
	if c.Signing != nil {
		policy = c.Signing
	} else {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
		policy.Default.CAConstraint.IsCA = true
	}

	// Make sure the policy reflects the new remote
	parentServerURL := ca.Config.Intermediate.ParentServer.URL
	if parentServerURL != "" {
		err = policy.OverrideRemotes(parentServerURL)
		if err != nil {
			return errors.Wrap(err, "Failed initializing enrollment signer")
		}
	}

	ca.enrollSigner, err = util.BccspBackedSigner(c.CA.Certfile, c.CA.Keyfile, policy, ca.csp)
	if err != nil {
		return err
	}
	ca.enrollSigner.SetDBAccessor(ca.certDBAccessor)

	// Successful enrollment
	return nil
}

// loadUsersTable adds the configured users to the table if not already found
func (ca *CA) loadUsersTable() error {
	log.Debug("Loading identity table")
	registry := &ca.Config.Registry
	for _, id := range registry.Identities {
		log.Debugf("Loading identity '%s'", id.Name)
		err := ca.addIdentity(&id, false)
		if err != nil {
			return errors.WithMessage(err, "Failed to load identity table")
		}
	}
	log.Debug("Successfully loaded identity table")
	return nil
}

// loadAffiliationsTable adds the configured affiliations to the table
func (ca *CA) loadAffiliationsTable() error {
	log.Debug("Loading affiliations table")
	err := ca.loadAffiliationsTableR(ca.Config.Affiliations, "")
	if err != nil {
		return errors.WithMessage(err, "Failed to load affiliations table")
	}
	log.Debug("Successfully loaded affiliations table")
	return nil
}

// Recursive function to load the affiliations table hierarchy
func (ca *CA) loadAffiliationsTableR(val interface{}, parentPath string) (err error) {
	var path string
	if val == nil {
		return nil
	}
	switch val.(type) {
	case string:
		path = affiliationPath(val.(string), parentPath)
		err = ca.addAffiliation(path, parentPath)
		if err != nil {
			return err
		}
	case []string:
		for _, ele := range val.([]string) {
			err = ca.loadAffiliationsTableR(ele, parentPath)
			if err != nil {
				return err
			}
		}
	case []interface{}:
		for _, ele := range val.([]interface{}) {
			err = ca.loadAffiliationsTableR(ele, parentPath)
			if err != nil {
				return err
			}
		}
	default:
		for name, ele := range val.(map[string]interface{}) {
			path = affiliationPath(name, parentPath)
			err = ca.addAffiliation(path, parentPath)
			if err != nil {
				return err
			}
			err = ca.loadAffiliationsTableR(ele, path)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Add an identity to the registry
func (ca *CA) addIdentity(id *CAConfigIdentity, errIfFound bool) error {
	var err error
	user, _ := ca.registry.GetUser(id.Name, nil)
	if user != nil {
		if errIfFound {
			return errors.Errorf("Identity '%s' is already registered", id.Name)
		}
		log.Debugf("Identity '%s' already registered, loaded identity", user.GetName())
		return nil
	}

	id.MaxEnrollments, err = getMaxEnrollments(id.MaxEnrollments, ca.Config.Registry.MaxEnrollments)
	if err != nil {
		return caerrors.NewFatalError(caerrors.ErrConfig, "Configuration Error: %s", err)
	}

	attrs, err := attr.ConvertAttrs(id.Attrs)

	if err != nil {
		return err
	}

	rec := cadbuser.Info{
		Name:           id.Name,
		Pass:           id.Pass,
		Type:           id.Type,
		Affiliation:    id.Affiliation,
		Attributes:     attrs,
		MaxEnrollments: id.MaxEnrollments,
		Level:          ca.levels.Identity,
	}
	err = ca.registry.InsertUser(&rec)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to insert identity '%s'", id.Name))
	}
	log.Debugf("Registered identity: %+v", id)
	return nil
}

func (ca *CA) addAffiliation(path, parentPath string) error {
	return ca.registry.InsertAffiliation(path, parentPath, ca.levels.Affiliation)
}

// CertDBAccessor returns the certificate DB accessor for CA
func (ca *CA) CertDBAccessor() *CertDBAccessor {
	return ca.certDBAccessor
}

// DBAccessor returns the registry DB accessor for server
func (ca *CA) DBAccessor() user.Registry {
	return ca.registry
}

// GetDB returns pointer to database
func (ca *CA) GetDB() db.FabricCADB {
	return ca.db
}

// GetCertificate returns a single certificate matching serial and aki, if multiple certificates
// found for serial and aki an error is returned
func (ca *CA) GetCertificate(serial, aki string) (*certdb.CertificateRecord, error) {
	certs, err := ca.CertDBAccessor().GetCertificate(serial, aki)
	if err != nil {
		return nil, caerrors.NewHTTPErr(500, caerrors.ErrCertNotFound, "Failed searching certificates: %s", err)
	}
	if len(certs) == 0 {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrCertNotFound, "Certificate not found with AKI '%s' and serial '%s'", aki, serial)
	}
	if len(certs) > 1 {
		return nil, caerrors.NewAuthenticationErr(caerrors.ErrCertNotFound, "Multiple certificates found, when only should exist with AKI '%s' and serial '%s' combination", aki, serial)
	}
	return &certs[0], nil
}

// Make all file names in the CA config absolute
func (ca *CA) makeFileNamesAbsolute() error {
	log.Debug("Making CA filenames absolute")

	fields := []*string{
		&ca.Config.CA.Certfile,
		&ca.Config.CA.Keyfile,
		&ca.Config.CA.Chainfile,
	}
	err := util.MakeFileNamesAbsolute(fields, ca.HomeDir)
	if err != nil {
		return err
	}
	err = tls.AbsTLSClient(&ca.Config.DB.TLS, ca.HomeDir)
	if err != nil {
		return err
	}
	err = tls.AbsTLSClient(&ca.Config.LDAP.TLS, ca.HomeDir)
	if err != nil {
		return err
	}
	return nil
}

// Convert all comma separated strings to string arrays
func (ca *CA) normalizeStringSlices() {
	fields := []*[]string{
		&ca.Config.CSR.Hosts,
		&ca.Config.DB.TLS.CertFiles,
		&ca.Config.LDAP.TLS.CertFiles,
	}
	for _, namePtr := range fields {
		norm := util.NormalizeStringSlice(*namePtr)
		*namePtr = norm
	}
}

// userHasAttribute returns nil error and the value of the attribute
// if the user has the attribute, or an appropriate error if the user
// does not have this attribute.
func (ca *CA) userHasAttribute(username, attrname string) (string, error) {
	val, err := ca.getUserAttrValue(username, attrname)
	if err != nil {
		return "", err
	}
	if val == "" {
		return "", errors.Errorf("Identity '%s' does not have attribute '%s'", username, attrname)
	}
	return val, nil
}

// attributeIsTrue returns nil if the attribute has
// one of the following values: "1", "t", "T", "true", "TRUE", "True";
// otherwise it will return an error
func (ca *CA) attributeIsTrue(username, attrname string) error {
	val, err := ca.userHasAttribute(username, attrname)
	if err != nil {
		return err
	}
	val2, err := strconv.ParseBool(val)
	if err != nil {
		return errors.Wrapf(err, "Invalid value for attribute '%s' of identity '%s'", attrname, username)
	}
	if val2 {
		return nil
	}
	return errors.Errorf("Attribute '%s' is not set to true for identity '%s'", attrname, username)
}

// getUserAttrValue returns a user's value for an attribute
func (ca *CA) getUserAttrValue(username, attrname string) (string, error) {
	log.Debugf("getUserAttrValue identity=%s, attr=%s", username, attrname)
	user, err := ca.registry.GetUser(username, []string{attrname})
	if err != nil {
		return "", err
	}
	attrval, err := user.GetAttribute(attrname)
	if err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("Failed to get attribute '%s' for user '%s'", attrname, user.GetName()))
	}
	log.Debugf("getUserAttrValue identity=%s, name=%s, value=%s", username, attrname, attrval)
	return attrval.Value, nil
}

// getUserAffiliation returns a user's affiliation
func (ca *CA) getUserAffiliation(username string) (string, error) {
	log.Debugf("getUserAffilliation identity=%s", username)
	user, err := ca.registry.GetUser(username, nil)
	if err != nil {
		return "", err
	}
	aff := cadbuser.GetAffiliation(user)
	log.Debugf("getUserAffiliation identity=%s, aff=%s", username, aff)
	return aff, nil
}

// fillCAInfo fills the CA info structure appropriately
func (ca *CA) fillCAInfo(info *common.CAInfoResponseNet) error {
	caChain, err := ca.getCAChain()
	if err != nil {
		return err
	}
	info.CAName = ca.Config.CA.Name
	info.CAChain = util.B64Encode(caChain)

	ipkBytes, err := ca.issuer.IssuerPublicKey()
	if err != nil {
		return err
	}
	rpkBytes, err := ca.issuer.RevocationPublicKey()
	if err != nil {
		return err
	}
	info.IssuerPublicKey = util.B64Encode(ipkBytes)
	info.IssuerRevocationPublicKey = util.B64Encode(rpkBytes)
	return nil
}

// Perfroms checks on the provided CA cert to make sure it's valid
func (ca *CA) validateCertAndKey(certFile string, keyFile string) error {
	log.Debug("Validating the CA certificate and key")
	var err error
	var certPEM []byte

	certPEM, err = ioutil.ReadFile(certFile)
	if err != nil {
		return errors.Wrapf(err, certificateError+" '%s'", certFile)
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}

	if err = validateDates(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateUsage(cert, ca.Config.CA.Name); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateIsCA(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateKeyType(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateKeySize(cert); err != nil {
		return errors.WithMessage(err, fmt.Sprintf(certificateError+" '%s'", certFile))
	}
	if err = validateMatchingKeys(cert, keyFile); err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Invalid certificate and/or key in files '%s' and '%s'", certFile, keyFile))
	}
	log.Debug("Validation of CA certificate and key successful")

	return nil
}

// Returns expiration of the CA certificate
func (ca *CA) getCACertExpiry() (time.Time, error) {
	var caexpiry time.Time
	signer, ok := ca.enrollSigner.(*cflocalsigner.Signer)
	if ok {
		cacert, err := signer.Certificate("", "ca")
		if err != nil {
			log.Errorf("Failed to get CA certificate for CA %s: %s", ca.Config.CA.Name, err)
			return caexpiry, err
		} else if cacert != nil {
			caexpiry = cacert.NotAfter
		}
	} else {
		log.Errorf("Not expected condition as the enrollSigner can only be cfssl/signer/local/Signer")
		return caexpiry, errors.New("Unexpected error while getting CA certificate expiration")
	}
	return caexpiry, nil
}

func canSignCRL(cert *x509.Certificate) bool {
	return cert.KeyUsage&x509.KeyUsageCRLSign != 0
}

func validateDates(cert *x509.Certificate) error {
	log.Debug("Check CA certificate for valid dates")

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}

func validateUsage(cert *x509.Certificate, caName string) error {
	log.Debug("Check CA certificate for valid usages")

	if cert.KeyUsage == 0 {
		return errors.New("No usage specified for certificate")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("The 'cert sign' key usage is required")
	}

	if !canSignCRL(cert) {
		log.Warningf("The CA certificate for the CA '%s' does not have 'crl sign' key usage, so the CA will not be able generate a CRL", caName)
	}
	return nil
}

func validateIsCA(cert *x509.Certificate) error {
	log.Debug("Check CA certificate for valid IsCA value")

	if !cert.IsCA {
		return errors.New("Certificate not configured to be used for CA")
	}

	return nil
}

func validateKeyType(cert *x509.Certificate) error {
	log.Debug("Check that key type is supported")

	switch cert.PublicKey.(type) {
	case *dsa.PublicKey:
		return errors.New("Unsupported key type: DSA")
	}

	return nil
}

func validateKeySize(cert *x509.Certificate) error {
	log.Debug("Check that key size is of appropriate length")

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		size := cert.PublicKey.(*rsa.PublicKey).N.BitLen()
		if size < 2048 {
			return errors.New("Key size is less than 2048 bits")
		}
	}

	return nil
}

func validateMatchingKeys(cert *x509.Certificate, keyFile string) error {
	log.Debug("Check that public key and private key match")

	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}

	pubKey := cert.PublicKey
	switch pubKey.(type) {
	case *rsa.PublicKey:
		privKey, err := util.GetRSAPrivateKey(keyPEM)
		if err != nil {
			return err
		}

		if privKey.PublicKey.N.Cmp(pubKey.(*rsa.PublicKey).N) != 0 {
			return errors.New("Public key and private key do not match")
		}
	case *ecdsa.PublicKey:
		privKey, err := util.GetECPrivateKey(keyPEM)
		if err != nil {
			return err
		}

		if privKey.PublicKey.X.Cmp(pubKey.(*ecdsa.PublicKey).X) != 0 {
			return errors.New("Public key and private key do not match")
		}
	}

	return nil
}

// Load CN from existing enrollment information
func (ca *CA) loadCNFromEnrollmentInfo(certFile string) (string, error) {
	log.Debug("Loading CN from existing enrollment information")
	cert, err := util.ReadFile(certFile)
	if err != nil {
		log.Debugf("No cert found at %s", certFile)
		return "", err
	}
	name, err := util.GetEnrollmentIDFromPEM(cert)
	if err != nil {
		return "", err
	}
	return name, nil
}

// This function returns an error if the version specified in the configuration file is greater than the server version
func (ca *CA) checkConfigLevels() error {
	var err error
	serverVersion := metadata.GetVersion()
	configVersion := ca.Config.Version
	log.Debugf("Checking configuration file version '%+v' against server version: '%+v'", configVersion, serverVersion)
	// Check configuration file version against server version to make sure that newer configuration file is not being used with server
	cmp, err := metadata.CmpVersion(configVersion, serverVersion)
	if err != nil {
		return errors.WithMessage(err, "Failed to compare version")
	}
	if cmp == -1 {
		return fmt.Errorf("Configuration file version '%s' is higher than server version '%s'", configVersion, serverVersion)
	}
	cfg, err := metadata.GetLevels(ca.Config.Version)
	if err != nil {
		return err
	}
	ca.levels = cfg
	return nil
}

func (ca *CA) checkDBLevels() error {
	// Check database table levels against server levels to make sure that a database levels are compatible with server
	levels, err := db.CurrentDBLevels(ca.db)
	if err != nil {
		return err
	}
	sl, err := metadata.GetLevels(metadata.GetVersion())
	if err != nil {
		return err
	}
	log.Debugf("Checking database levels '%+v' against server levels '%+v'", levels, sl)
	if (levels.Identity > sl.Identity) || (levels.Affiliation > sl.Affiliation) || (levels.Certificate > sl.Certificate) ||
		(levels.Credential > sl.Credential) || (levels.Nonce > sl.Nonce) || (levels.RAInfo > sl.RAInfo) {
		return caerrors.NewFatalError(caerrors.ErrDBLevel, "The version of the database is newer than the server version.  Upgrade your server.")
	}
	return nil
}

func writeFile(file string, buf []byte, perm os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(file), 0755)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, buf, perm)
}

func affiliationPath(name, parent string) string {
	if parent == "" {
		return name
	}
	return fmt.Sprintf("%s.%s", parent, name)
}

func parseDuration(str string) time.Duration {
	d, err := time.ParseDuration(str)
	if err != nil {
		panic(err)
	}
	return d
}

func initSigningProfile(spp **config.SigningProfile, expiry time.Duration, isCA bool) {
	sp := *spp
	if sp == nil {
		sp = &config.SigningProfile{CAConstraint: config.CAConstraint{IsCA: isCA}}
		*spp = sp
	}
	if sp.Usage == nil {
		sp.Usage = []string{"cert sign", "crl sign"}
	}
	if sp.Expiry == 0 {
		sp.Expiry = expiry
	}
	if sp.ExtensionWhitelist == nil {
		sp.ExtensionWhitelist = map[string]bool{}
	}
	// This is set so that all profiles permit an attribute extension in CFSSL
	sp.ExtensionWhitelist[attrmgr.AttrOIDString] = true
}

type wallClock struct{}

func (wc wallClock) Now() time.Time {
	return time.Now()
}

func getMigrator(driverName string, tx cadb.FabricCATx, curLevels, srvLevels *dbutil.Levels) (cadb.Migrator, error) {
	var migrator cadb.Migrator
	switch driverName {
	case "sqlite3":
		migrator = sqlite.NewMigrator(tx, curLevels, srvLevels)
	case "mysql":
		migrator = mysql.NewMigrator(tx, curLevels, srvLevels)
	case "postgres":
		migrator = postgres.NewMigrator(tx, curLevels, srvLevels)
	default:
		return nil, errors.Errorf("Unsupported database type: %s", driverName)
	}
	return migrator, nil
}
