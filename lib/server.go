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
	_ "net/http/pprof" // enables profiling
)

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/viper"

	_ "github.com/go-sql-driver/mysql" // import to support MySQL
	_ "github.com/lib/pq"              // import to support Postgres
	_ "github.com/mattn/go-sqlite3"    // import to support SQLite3
)

const (
	defaultClientAuth         = "noclientcert"
	fabricCAServerProfilePort = "FABRIC_CA_SERVER_PROFILE_PORT"
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
	mux *http.ServeMux
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
}

// Init initializes a fabric-ca server
func (s *Server) Init(renew bool) (err error) {

	if s.Config.CAcount != 0 && len(s.Config.CAfiles) > 0 {
		return fmt.Errorf("Can't set values for both cacount and cafiles")
	}

	// Initialize the config, setting defaults, etc
	err = s.initConfig()
	if err != nil {
		return err
	}
	// Initialize the default CA hosted by the server
	err = s.initDefaultCA(&s.CA, renew)
	if err != nil {
		return err
	}
	// Initialize any additional CAs beside the default CA
	if len(s.Config.CAfiles) > 0 {
		err = s.initCAs()
		if err != nil {
			return err
		}
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
	err = s.Init(false)
	if err != nil {
		return err
	}

	// Register http handlers
	s.registerHandlers()

	log.Debugf("%d CA instance(s) running on server", len(s.caMap))

	// Start listening and serving
	return s.listenAndServe()

}

// Stop the server
// WARNING: This forcefully closes the listening socket and may cause
// requests in transit to fail, and so is only used for testing.
// A graceful shutdown will be supported with golang 1.8.
func (s *Server) Stop() error {
	if s.listener == nil {
		return errors.New("server is not currently started")
	}
	err := s.listener.Close()
	s.listener = nil
	return err
}

// RegisterBootstrapUser registers the bootstrap user with appropriate privileges
func (s *Server) RegisterBootstrapUser(user, pass, affiliation string) error {
	// Initialize the config, setting defaults, etc
	log.Debugf("RegisterBootstrapUser - identity: %s, Pass: %s, affiliation: %s", user, pass, affiliation)

	if user == "" || pass == "" {
		return errors.New("Empty identity name and/or pass not allowed")
	}

	id := CAConfigIdentity{
		Name:           user,
		Pass:           pass,
		Type:           "user",
		Affiliation:    affiliation,
		MaxEnrollments: s.CA.Config.Registry.MaxEnrollments,
		Attrs: map[string]string{
			"hf.Registrar.Roles":         "client,user,peer,validator,auditor",
			"hf.Registrar.DelegateRoles": "client,user,validator,auditor",
			"hf.Revoker":                 "true",
			"hf.IntermediateCA":          "true",
		},
	}

	registry := &s.CA.Config.Registry
	registry.Identities = append(registry.Identities, id)

	log.Debugf("Registered bootstrap identity: %+v", &id)
	return nil
}

// Initialize the config, setting any defaults and making filenames absolute
func (s *Server) initConfig() (err error) {
	// Init home directory if not set
	if s.HomeDir == "" {
		s.HomeDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("Failed to get server's home directory: %s", err)
		}
	}
	s.caMap = make(map[string]*CA)
	s.caConfigMap = make(map[string]*CAConfig)

	// Init config if not set
	if s.Config == nil {
		s.Config = new(ServerConfig)
	}
	// Set config defaults
	cfg := s.Config
	if cfg.Address == "" {
		cfg.Address = DefaultServerAddr
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultServerPort
	}
	// Set log level if debug is true
	if cfg.Debug {
		log.Level = log.LevelDebug
	}

	cfg.CAfiles, err = util.NormalizeFileList(cfg.CAfiles, s.HomeDir)
	if err != nil {
		return err
	}

	if cfg.CAcount >= 1 {
		s.createDefaultCAConfigs(cfg.CAcount)
	}

	if len(s.Config.CAfiles) != 0 {
		log.Debugf("Default CA configuration, if necessary, will be used to replace missing values for additional CAs: %+v", s.Config.CAcfg)
		log.Debugf("Additional CAs to be started: %s", cfg.CAfiles)
		var caFiles []string

		caFiles = util.NormalizeStringSlice(cfg.CAfiles)

		for _, caFile := range caFiles {
			err = s.loadCAConfig(caFile, false)
			if err != nil {
				return err
			}
		}
	}

	// Make file names absolute
	s.makeFileNamesAbsolute()
	// Create empty CA map
	return nil
}

func (s *Server) initDefaultCA(ca *CA, renew bool) error {
	log.Debug("Initializing default ca")

	err := initCA(ca, s.HomeDir, s.CA.Config, s, renew)
	if err != nil {
		return err
	}

	s.caMap[ca.Config.CA.Name] = ca

	log.Infof("Home directory for default CA: %s", ca.HomeDir)

	return nil
}

// loadCAConfig loads up a CA's configuration from the specified
// CA configuration file
func (s *Server) loadCAConfig(caFile string, renew bool) error {
	log.Infof("Loading CA from %s", caFile)
	var err error

	caConfig := new(CAConfig)

	exists := util.FileExists(caFile)
	if !exists {
		return fmt.Errorf("%s file does not exist", caFile)
	}

	// Creating new Viper instance, to prevent any server level environment variables or
	// flags from overridding the configuration options specified in the
	// CA config file
	caViper := viper.New()

	err = UnmarshalConfig(caConfig, caViper, caFile, false, true)
	if err != nil {
		return err
	}

	// Need to error if no CA name provided in config file, we cannot revert to using
	// the name of default CA cause CA names must be unique
	if caConfig.CA.Name == "" {
		return fmt.Errorf("No CA name provided in CA configuration file. CA name is required in %s", caFile)
	}

	// Replace missing values in CA configuration values with values from the
	// default CA configuration
	util.CopyMissingValues(s.CA.Config, caConfig)

	// SWOpts is a pointer, we don't want CA config to point to
	// default ca config. SWOpts will be initialized when CA
	// is created and initialized (see NewCA)
	if caConfig.CSP != nil {
		caConfig.CSP = nil
	}

	// Integers and boolean values are handled outside the util.CopyMissingValues
	// because there is no way through reflect to detect if a value was explicitly
	// set to 0 or false, or it is using the default value for its type. Viper is
	// employed here to help detect.
	if !caViper.IsSet("registry.maxenrollments") {
		caConfig.Registry.MaxEnrollments = s.CA.Config.Registry.MaxEnrollments
	}

	if !caViper.IsSet("db.tls.enabled") {
		caConfig.DB.TLS.Enabled = s.CA.Config.DB.TLS.Enabled
	}

	log.Debugf("CA configuration after checking for missing value: %+v", caConfig)

	for _, config := range s.caConfigMap {
		if config.CSR.CN == caConfig.CSR.CN {
			return fmt.Errorf("Common Name (CN) is already in use by another CA, please specify a unique CN in %s", caFile)
		}
		if config.CA.Name == caConfig.CA.Name {
			return fmt.Errorf("CA by name '%s' in %s already exists", caConfig.CA.Name, caFile)
		}
	}

	s.caConfigMap[caFile] = caConfig

	return nil
}

// startCA initializes the CA
func (s *Server) initCAs() error {
	var ca *CA
	var err error

	for configFile, caConfig := range s.caConfigMap {
		log.Debugf("Initalizing CA %s", caConfig.CA.Name)

		ca, err = NewCA(filepath.Dir(configFile), caConfig, s, true)
		if err != nil {
			return err
		}

		s.caMap[ca.Config.CA.Name] = ca
		log.Infof("Home directory for CA '%s': %s", ca.Config.CA.Name, ca.HomeDir)
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

// Register all endpoint handlers
func (s *Server) registerHandlers() {
	s.mux = http.NewServeMux()
	s.registerHandler("cainfo", newInfoHandler, noAuth)
	s.registerHandler("register", newRegisterHandler, token)
	s.registerHandler("enroll", newEnrollHandler, basic)
	s.registerHandler("reenroll", newReenrollHandler, token)
	s.registerHandler("revoke", newRevokeHandler, token)
	s.registerHandler("tcert", newTCertHandler, token)
}

// Register an endpoint handler
func (s *Server) registerHandler(
	path string,
	getHandler func(server *Server) (http.Handler, error),
	at authType) {

	var handler http.Handler

	handler, err := getHandler(s)
	if err != nil {
		log.Warningf("Endpoint '%s' is disabled: %s", path, err)
		return
	}

	handler = &fcaAuthHandler{
		server:   s,
		authType: at,
		next:     handler,
	}
	s.mux.Handle("/"+path, handler)
	s.mux.Handle("/api/v1/"+path, handler)
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

	if c.TLS.Enabled {
		log.Debug("TLS is enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
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
			Certificates: []tls.Certificate{cer},
			ClientAuth:   clientAuth,
			ClientCAs:    certPool,
		}

		listener, err = tls.Listen("tcp", addr, config)
		if err != nil {
			return fmt.Errorf("TLS listen failed: %s", err)
		}
		log.Infof("Listening at https://%s", addr)
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen failed: %s", err)
		}
		log.Infof("Listening at http://%s", addr)
	}
	s.listener = listener

	err = s.checkAndEnableProfiling()
	if err != nil {
		s.listener.Close()
		s.listener = nil
		return fmt.Errorf("TCP listen for profiling failed: %s", err)
	}

	// Start serving requests, either blocking or non-blocking
	if s.BlockingStart {
		return s.serve()
	}
	go s.serve()
	return nil
}

func (s *Server) serve() error {
	s.serveError = http.Serve(s.listener, s.mux)
	log.Errorf("Server has stopped serving: %s", s.serveError)
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
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

	fields := []*string{
		&s.Config.TLS.CertFile,
		&s.Config.TLS.KeyFile,
	}
	for _, namePtr := range fields {
		abs, err := util.MakeFileAbs(*namePtr, s.HomeDir)
		if err != nil {
			return err
		}
		*namePtr = abs
	}
	return nil
}
