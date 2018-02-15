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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof" // import to support profiling
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/cloudflare/cfssl/signer"
	gmux "github.com/gorilla/mux"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	stls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"
)

const (
	defaultClientAuth         = "noclientcert"
	fabricCAServerProfilePort = "FABRIC_CA_SERVER_PROFILE_PORT"
	allRoles                  = "peer,orderer,client,user"
	apiPathPrefix             = "/api/v1/"
)

// Server is the fabric-ca server
type Server struct {
	// The home directory for the server
	HomeDir string
	// BlockingStart if true makes the Start function blocking;
	// It is non-blocking by default.
	BlockingStart bool
	// The server's configuration
	Config *ServerConfig
	// The server mux
	mux *gmux.Router
	// The current listener for this server
	listener net.Listener
	// An error which occurs when serving
	serveError error
	// Server's default CA
	CA
	// A map of CAs stored by CA name as key
	caMap map[string]*CA
	// A map of CA configs stored by CA file as key
	caConfigMap map[string]*CAConfig
	// channel for communication between http.serve and main threads.
	wait chan bool
	// Server mutex
	mutex sync.Mutex
	// The server's current levels
	levels *dbutil.Levels
}

// Init initializes a fabric-ca server
func (s *Server) Init(renew bool) (err error) {
	err = s.init(renew)
	err2 := s.closeDB()
	if err2 != nil {
		log.Errorf("Close DB failed: %s", err2)
	}
	return err
}

// init initializses the server leaving the DB open
func (s *Server) init(renew bool) (err error) {
	serverVersion := metadata.GetVersion()
	log.Infof("Server Version: %s", serverVersion)
	s.levels, err = metadata.GetLevels(serverVersion)
	if err != nil {
		return err
	}
	log.Infof("Server Levels: %+v", s.levels)

	// Initialize the config
	err = s.initConfig()
	if err != nil {
		return err
	}
	// Initialize the default CA last
	err = s.initDefaultCA(renew)
	if err != nil {
		return err
	}
	// Successful initialization
	return nil
}

// Start the fabric-ca server
func (s *Server) Start() (err error) {
	log.Infof("Starting server in home directory: %s", s.HomeDir)

	s.serveError = nil

	if s.listener != nil {
		return errors.New("server is already started")
	}

	// Initialize the server
	err = s.init(false)
	if err != nil {
		err2 := s.closeDB()
		if err2 != nil {
			log.Errorf("Close DB failed: %s", err2)
		}
		return err
	}

	// Register http handlers
	s.registerHandlers()

	log.Debugf("%d CA instance(s) running on server", len(s.caMap))

	// Start listening and serving
	err = s.listenAndServe()
	if err != nil {
		err2 := s.closeDB()
		if err2 != nil {
			log.Errorf("Close DB failed: %s", err2)
		}
		return err
	}
	return nil
}

// Stop the server
// WARNING: This forcefully closes the listening socket and may cause
// requests in transit to fail, and so is only used for testing.
// A graceful shutdown will be supported with golang 1.8.
func (s *Server) Stop() error {
	err := s.closeListener()
	if err != nil {
		return err
	}
	if s.wait == nil {
		return nil
	}
	// Wait for message on wait channel from the http.serve thread. If message
	// is not received in 10 seconds, return
	port := s.Config.Port
	for i := 0; i < 10; i++ {
		select {
		case <-s.wait:
			log.Debugf("Stop: successful stop on port %d", port)
			close(s.wait)
			s.wait = nil
			return nil
		default:
			log.Debugf("Stop: waiting for listener on port %d to stop", port)
			time.Sleep(time.Second)
		}
	}
	log.Debugf("Stop: timed out waiting for stop notification for port %d", port)
	// make sure DB is closed
	err = s.closeDB()
	if err != nil {
		log.Errorf("Close DB failed: %s", err)
	}
	return nil
}

// RegisterBootstrapUser registers the bootstrap user with appropriate privileges
func (s *Server) RegisterBootstrapUser(user, pass, affiliation string) error {
	// Initialize the config, setting defaults, etc
	log.Debugf("Register bootstrap user: name=%s, affiliation=%s", user, affiliation)

	if user == "" || pass == "" {
		return errors.New("Empty identity name and/or pass not allowed")
	}

	id := CAConfigIdentity{
		Name:           user,
		Pass:           pass,
		Type:           "client",
		Affiliation:    affiliation,
		MaxEnrollments: 0, // 0 means to use the server's max enrollment setting
		Attrs: map[string]string{
			attr.Roles:          allRoles,
			attr.DelegateRoles:  allRoles,
			attr.Revoker:        "true",
			attr.IntermediateCA: "true",
			attr.GenCRL:         "true",
			attr.RegistrarAttr:  "*",
			attr.AffiliationMgr: "true",
		},
	}

	registry := &s.CA.Config.Registry
	registry.Identities = append(registry.Identities, id)

	log.Debugf("Registered bootstrap identity: %+v", id)
	return nil
}

// initConfig initializes the configuration for the server
func (s *Server) initConfig() (err error) {
	// Home directory is current working directory by default
	if s.HomeDir == "" {
		s.HomeDir, err = os.Getwd()
		if err != nil {
			return errors.Wrap(err, "Failed to get server's home directory")
		}
	}
	// Make home directory absolute, if not already
	absoluteHomeDir, err := filepath.Abs(s.HomeDir)
	if err != nil {
		return fmt.Errorf("Failed to make server's home directory path absolute: %s", err)
	}
	s.HomeDir = absoluteHomeDir
	// Create config if not set
	if s.Config == nil {
		s.Config = new(ServerConfig)
	}
	cfg := s.Config
	// Set log level if debug is true
	if cfg.Debug {
		log.Level = log.LevelDebug
	}
	s.CA.server = s
	s.CA.HomeDir = s.HomeDir
	err = s.initMultiCAConfig()
	if err != nil {
		return err
	}
	revoke.SetCRLFetcher(s.fetchCRL)
	// Make file names absolute
	s.makeFileNamesAbsolute()
	return nil
}

// Initialize config related to multiple CAs
func (s *Server) initMultiCAConfig() (err error) {
	cfg := s.Config
	if cfg.CAcount != 0 && len(cfg.CAfiles) > 0 {
		return errors.New("The --cacount and --cafiles options are mutually exclusive")
	}
	cfg.CAfiles, err = util.NormalizeFileList(cfg.CAfiles, s.HomeDir)
	if err != nil {
		return err
	}
	// Multi-CA related configuration initialization
	s.caMap = make(map[string]*CA)
	if cfg.CAcount >= 1 {
		s.createDefaultCAConfigs(cfg.CAcount)
	}
	if len(cfg.CAfiles) != 0 {
		log.Debugf("Default CA configuration, if necessary, will be used to replace missing values for additional CAs: %+v", s.Config.CAcfg)
		log.Debugf("Additional CAs to be started: %s", cfg.CAfiles)
		var caFiles []string
		caFiles = util.NormalizeStringSlice(cfg.CAfiles)
		for _, caFile := range caFiles {
			err = s.loadCA(caFile, false)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) initDefaultCA(renew bool) error {
	log.Debugf("Initializing default CA in directory %s", s.HomeDir)
	ca := &s.CA
	err := initCA(ca, s.HomeDir, s.CA.Config, s, renew)
	if err != nil {
		return err
	}
	err = s.addCA(ca)
	if err != nil {
		return err
	}
	log.Infof("Home directory for default CA: %s", ca.HomeDir)
	return nil
}

// loadCAConfig loads up a CA's configuration from the specified
// CA configuration file
func (s *Server) loadCA(caFile string, renew bool) error {
	log.Infof("Loading CA from %s", caFile)
	var err error

	if !util.FileExists(caFile) {
		return errors.Errorf("%s file does not exist", caFile)
	}

	// Creating new Viper instance, to prevent any server level environment variables or
	// flags from overridding the configuration options specified in the
	// CA config file
	cfg := &CAConfig{}
	caViper := viper.New()
	err = UnmarshalConfig(cfg, caViper, caFile, false)
	if err != nil {
		return err
	}

	// Need to error if no CA name provided in config file, we cannot revert to using
	// the name of default CA cause CA names must be unique
	caName := cfg.CA.Name
	if caName == "" {
		return errors.Errorf("No CA name provided in CA configuration file. CA name is required in %s", caFile)
	}

	// Replace missing values in CA configuration values with values from the
	// defaut CA configuration
	util.CopyMissingValues(s.CA.Config, cfg)

	// Integers and boolean values are handled outside the util.CopyMissingValues
	// because there is no way through reflect to detect if a value was explicitly
	// set to 0 or false, or it is using the default value for its type. Viper is
	// employed here to help detect.
	if !caViper.IsSet("registry.maxenrollments") {
		cfg.Registry.MaxEnrollments = s.CA.Config.Registry.MaxEnrollments
	}

	if !caViper.IsSet("db.tls.enabled") {
		cfg.DB.TLS.Enabled = s.CA.Config.DB.TLS.Enabled
	}

	log.Debugf("CA configuration after checking for missing values: %+v", cfg)

	ca, err := newCA(caFile, cfg, s, renew)
	if err != nil {
		return err
	}
	err = s.addCA(ca)
	if err != nil {
		err2 := ca.closeDB()
		if err2 != nil {
			log.Errorf("Close DB failed: %s", err2)
		}
	}
	return err
}

// DN is the distinguished name inside a certificate
type DN struct {
	issuer  string
	subject string
}

// addCA adds a CA to the server if there are no conflicts
func (s *Server) addCA(ca *CA) error {
	// check for conflicts
	caName := ca.Config.CA.Name
	for _, c := range s.caMap {
		if c.Config.CA.Name == caName {
			return errors.Errorf("CA name '%s' is used in '%s' and '%s'",
				caName, ca.ConfigFilePath, c.ConfigFilePath)
		}
		err := s.compareDN(c.Config.CA.Certfile, ca.Config.CA.Certfile)
		if err != nil {
			return err
		}
	}
	// no conflicts, so add it
	s.caMap[caName] = ca

	return nil
}

// closeDB closes all CA dabatases
func (s *Server) closeDB() error {
	log.Debugf("Closing server DBs")
	// close default CA DB
	err := s.CA.closeDB()
	if err != nil {
		return err
	}
	// close other CAs DB
	for _, c := range s.caMap {
		err = c.closeDB()
		if err != nil {
			return err
		}
	}
	return nil
}

// createDefaultCAConfigs creates specified number of default CA configuration files
func (s *Server) createDefaultCAConfigs(cacount int) error {
	log.Debugf("Creating %d default CA configuration files", cacount)

	cashome, err := util.MakeFileAbs("ca", s.HomeDir)
	if err != nil {
		return err
	}

	os.Mkdir(cashome, 0755)

	for i := 1; i <= cacount; i++ {
		cahome := fmt.Sprintf(cashome+"/ca%d", i)
		cfgFileName := filepath.Join(cahome, "fabric-ca-config.yaml")

		caName := fmt.Sprintf("ca%d", i)
		cfg := strings.Replace(defaultCACfgTemplate, "<<<CANAME>>>", caName, 1)

		cn := fmt.Sprintf("fabric-ca-server-ca%d", i)
		cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", cn, 1)

		datasource := dbutil.GetCADataSource(s.CA.Config.DB.Type, s.CA.Config.DB.Datasource, i)
		cfg = strings.Replace(cfg, "<<<DATASOURCE>>>", datasource, 1)

		s.Config.CAfiles = append(s.Config.CAfiles, cfgFileName)

		// Now write the file
		err := os.MkdirAll(filepath.Dir(cfgFileName), 0755)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(cfgFileName, []byte(cfg), 0644)
		if err != nil {
			return err
		}

	}
	return nil
}

// GetCA returns the CA given its name
func (s *Server) GetCA(name string) (*CA, error) {
	// Lookup the CA from the server
	ca := s.caMap[name]
	if ca == nil {
		return nil, newHTTPErr(404, ErrCANotFound, "CA '%s' does not exist", name)
	}
	return ca, nil
}

// Register all endpoint handlers
func (s *Server) registerHandlers() {
	s.mux = gmux.NewRouter()
	s.registerHandler("cainfo", newCAInfoEndpoint(s))
	s.registerHandler("register", newRegisterEndpoint(s))
	s.registerHandler("enroll", newEnrollEndpoint(s))
	s.registerHandler("reenroll", newReenrollEndpoint(s))
	s.registerHandler("revoke", newRevokeEndpoint(s))
	s.registerHandler("tcert", newTCertEndpoint(s))
	s.registerHandler("gencrl", newGenCRLEndpoint(s))
	s.registerHandler("identities", newIdentitiesStreamingEndpoint(s))
	s.registerHandler("identities/{id}", newIdentitiesEndpoint(s))
	s.registerHandler("affiliations", newAffiliationsStreamingEndpoint(s))
	s.registerHandler("affiliations/{affiliation}", newAffiliationsEndpoint(s))
}

// Register a handler
func (s *Server) registerHandler(path string, se *serverEndpoint) {
	s.mux.Handle("/"+path, se)
	s.mux.Handle(apiPathPrefix+path, se)
}

// Starting listening and serving
func (s *Server) listenAndServe() (err error) {

	var listener net.Listener
	var clientAuth tls.ClientAuthType
	var ok bool

	c := s.Config

	// Set default listening address and port
	if c.Address == "" {
		c.Address = DefaultServerAddr
	}
	if c.Port == 0 {
		c.Port = DefaultServerPort
	}
	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	var addrStr string

	if c.TLS.Enabled {
		log.Debug("TLS is enabled")
		addrStr = fmt.Sprintf("https://%s", addr)

		// If key file is specified and it does not exist or its corresponding certificate file does not exist
		// then need to return error and not start the server. The TLS key file is specified when the user
		// wants the server to use custom tls key and cert and don't want server to auto generate its own. So,
		// when the key file is specified, it must exist on the file system
		if c.TLS.KeyFile != "" {
			if !util.FileExists(c.TLS.KeyFile) {
				return fmt.Errorf("File specified by 'tls.keyfile' does not exist: %s", c.TLS.KeyFile)
			}
			if !util.FileExists(c.TLS.CertFile) {
				return fmt.Errorf("File specified by 'tls.certfile' does not exist: %s", c.TLS.CertFile)
			}
		} else if !util.FileExists(c.TLS.CertFile) {
			// TLS key file is not specified, generate TLS key and cert if they are not already generated
			err = s.autoGenerateTLSCertificateKey()
			if err != nil {
				return fmt.Errorf("Failed to automatically generate TLS certificate and key: %s", err)
			}
		}
		log.Debugf("TLS Certificate: %s, TLS Key: %s", c.TLS.CertFile, c.TLS.KeyFile)

		cer, err := util.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile, s.csp)
		if err != nil {
			return err
		}

		if c.TLS.ClientAuth.Type == "" {
			c.TLS.ClientAuth.Type = defaultClientAuth
		}

		log.Debugf("Client authentication type requested: %s", c.TLS.ClientAuth.Type)

		authType := strings.ToLower(c.TLS.ClientAuth.Type)
		if clientAuth, ok = clientAuthTypes[authType]; !ok {
			return errors.New("Invalid client auth type provided")
		}

		var certPool *x509.CertPool
		if authType != defaultClientAuth {
			certPool, err = LoadPEMCertPool(c.TLS.ClientAuth.CertFiles)
			if err != nil {
				return err
			}
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{*cer},
			ClientAuth:   clientAuth,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		}

		listener, err = tls.Listen("tcp", addr, config)
		if err != nil {
			return errors.Wrapf(err, "TLS listen failed for %s", addrStr)
		}
	} else {
		addrStr = fmt.Sprintf("http://%s", addr)
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrapf(err, "TCP listen failed for %s", addrStr)
		}
	}
	s.listener = listener
	log.Infof("Listening on %s", addrStr)

	err = s.checkAndEnableProfiling()
	if err != nil {
		s.closeListener()
		return errors.WithMessage(err, "TCP listen for profiling failed")
	}

	// Start serving requests, either blocking or non-blocking
	if s.BlockingStart {
		return s.serve()
	}
	s.wait = make(chan bool)
	go s.serve()

	return nil
}

func (s *Server) serve() error {
	listener := s.listener
	if listener == nil {
		// This can happen as follows:
		// 1) listenAndServe above is called with s.BlockingStart set to false
		//    and returns to the caller
		// 2) the caller immediately calls s.Stop, which sets s.listener to nil
		// 3) the go routine runs and calls this function
		// So this prevents the panic which was reported in
		// in https://jira.hyperledger.org/browse/FAB-3100.
		return nil
	}
	s.serveError = http.Serve(listener, s.mux)
	log.Errorf("Server has stopped serving: %s", s.serveError)
	s.closeListener()
	err := s.closeDB()
	if err != nil {
		log.Errorf("Close DB failed: %s", err)
	}
	if s.wait != nil {
		s.wait <- true
	}
	return s.serveError
}

// checkAndEnableProfiling checks for FABRIC_CA_SERVER_PROFILE_PORT env variable
// if it is set, starts listening for profiling requests at the port specified
// by the environment variable
func (s *Server) checkAndEnableProfiling() error {
	// Start listening for profile requests
	pport := os.Getenv(fabricCAServerProfilePort)
	if pport != "" {
		iport, err := strconv.Atoi(pport)
		if err != nil || iport < 0 {
			log.Warningf("Profile port specified by the %s environment variable is not a valid port, not enabling profiling",
				fabricCAServerProfilePort)
		} else {
			addr := net.JoinHostPort(s.Config.Address, pport)
			listener, err1 := net.Listen("tcp", addr)
			log.Infof("Profiling enabled; listening for profile requests on port %s", pport)
			if err1 != nil {
				return err1
			}
			go func() {
				log.Debugf("Profiling enabled; waiting for profile requests on port %s", pport)
				err := http.Serve(listener, nil)
				log.Errorf("Stopped serving for profiling requests on port %s: %s", pport, err)
			}()
		}
	}
	return nil
}

// Make all file names in the config absolute
func (s *Server) makeFileNamesAbsolute() error {
	log.Debug("Making server filenames absolute")
	err := stls.AbsTLSServer(&s.Config.TLS, s.HomeDir)
	if err != nil {
		return err
	}
	return nil
}

// closeListener closes the listening endpoint
func (s *Server) closeListener() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	port := s.Config.Port
	if s.listener == nil {
		msg := fmt.Sprintf("Stop: listener was already closed on port %d", port)
		log.Debugf(msg)
		return errors.New(msg)
	}
	err := s.listener.Close()
	s.listener = nil
	if err != nil {
		log.Debugf("Stop: failed to close listener on port %d: %s", port, err)
		return err
	}
	log.Debugf("Stop: successfully closed listener on port %d", port)
	return nil
}

func (s *Server) compareDN(existingCACertFile, newCACertFile string) error {
	log.Debugf("Comparing DNs from certificates: %s and %s", existingCACertFile, newCACertFile)
	existingDN, err := s.loadDNFromCertFile(existingCACertFile)
	if err != nil {
		return err
	}

	newDN, err := s.loadDNFromCertFile(newCACertFile)
	if err != nil {
		return err
	}

	err = existingDN.equal(newDN)
	if err != nil {
		return errors.Wrapf(err, "Please modify CSR in %s and try adding CA again", newCACertFile)
	}
	return nil
}

// Read the CRL from body of http response
func (s *Server) fetchCRL(r io.Reader) ([]byte, error) {
	crlSizeLimit := s.Config.CRLSizeLimit
	log.Debugf("CRL size limit is %d bytes", crlSizeLimit)

	crl := make([]byte, crlSizeLimit)

	crl, err := util.Read(r, crl)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Error reading CRL with max buffer size of %d", crlSizeLimit))
	}

	return crl, nil
}

func (s *Server) loadDNFromCertFile(certFile string) (*DN, error) {
	log.Debugf("Loading DNs from certificate %s", certFile)
	cert, err := util.GetX509CertificateFromPEMFile(certFile)
	if err != nil {
		return nil, err
	}
	issuerDN, err := s.getDNFromCert(cert.Issuer, "/")
	if err != nil {
		return nil, err
	}
	subjectDN, err := s.getDNFromCert(cert.Subject, "/")
	if err != nil {
		return nil, err
	}
	distinguishedName := &DN{
		issuer:  issuerDN,
		subject: subjectDN,
	}
	return distinguishedName, nil
}

func (s *Server) autoGenerateTLSCertificateKey() error {
	log.Debug("TLS enabled but no certificate or key provided, automatically generate TLS credentials")

	clientCfg := &ClientConfig{
		CSP: s.CA.Config.CSP,
	}
	client := Client{
		HomeDir: s.HomeDir,
		Config:  clientCfg,
	}

	// Generate CSR that will be used to create the TLS certificate
	csrReq := s.Config.CAcfg.CSR
	csrReq.CA = nil // Not requesting a CA certificate
	hostname := util.Hostname()
	log.Debugf("TLS CSR: %+v\n", csrReq)

	// Can't use the same CN as the signing certificate CN (default: fabric-ca-server) otherwise no AKI is generated
	csr, _, err := client.GenCSR(&csrReq, hostname)
	if err != nil {
		return fmt.Errorf("Failed to generate CSR: %s", err)
	}

	// Use the 'tls' profile that will return a certificate with the appropriate extensions
	req := signer.SignRequest{
		Profile: "tls",
		Request: string(csr),
	}

	// Use default CA to get back signed TLS certificate
	cert, err := s.CA.enrollSigner.Sign(req)
	if err != nil {
		return fmt.Errorf("Failed to generate TLS certificate: %s", err)
	}

	// Write the TLS certificate to the file system
	ioutil.WriteFile(s.Config.TLS.CertFile, cert, 0644)

	return nil
}

func (dn *DN) equal(checkDN *DN) error {
	log.Debugf("Check to see if two DNs are equal - %+v and %+v", dn, checkDN)
	if dn.issuer == checkDN.issuer {
		log.Debug("Issuer distinguished name already in use, checking for unique subject distinguished name")
		if dn.subject == checkDN.subject {
			return errors.New("Both issuer and subject distinguished name are already in use")
		}
	}
	return nil
}

func (s *Server) getDNFromCert(namespace pkix.Name, sep string) (string, error) {
	subject := []string{}
	for _, s := range namespace.ToRDNSequence() {
		for _, i := range s {
			if v, ok := i.Value.(string); ok {
				if name, ok := oid[i.Type.String()]; ok {
					// <oid name>=<value>
					subject = append(subject, fmt.Sprintf("%s=%s", name, v))
				} else {
					// <oid>=<value> if no <oid name> is found
					subject = append(subject, fmt.Sprintf("%s=%s", i.Type.String(), v))
				}
			} else {
				// <oid>=<value in default format> if value is not string
				subject = append(subject, fmt.Sprintf("%s=%v", i.Type.String(), v))
			}
		}
	}
	return sep + strings.Join(subject, sep), nil
}

var oid = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "streetAddress",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.17":                   "postalCode",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generationQualifier",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.1":  "userid",
}
