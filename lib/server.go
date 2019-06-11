/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/cloudflare/cfssl/signer"
	"github.com/felixge/httpsnoop"
	ghandlers "github.com/gorilla/handlers"
	gmux "github.com/gorilla/mux"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	calog "github.com/hyperledger/fabric-ca/lib/common/log"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	servermetrics "github.com/hyperledger/fabric-ca/lib/server/metrics"
	"github.com/hyperledger/fabric-ca/lib/server/operations"
	stls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/healthz"
	"github.com/hyperledger/fabric/common/metrics"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	defaultClientAuth         = "noclientcert"
	fabricCAServerProfilePort = "FABRIC_CA_SERVER_PROFILE_PORT"
	allRoles                  = "peer,orderer,client,user"
	apiPathPrefix             = "/api/v1/"
)

//go:generate counterfeiter -o mocks/operations_server.go -fake-name OperationsServer . operationsServer

// operationsServer defines the contract required for an operations server
type operationsServer interface {
	metrics.Provider
	Start() error
	Stop() error
	Addr() string
	RegisterChecker(component string, checker healthz.HealthChecker) error
}

// Server is the fabric-ca server
type Server struct {
	// The home directory for the server.
	HomeDir string
	// BlockingStart determines if Start is blocking.
	// It is non-blocking by default.
	BlockingStart bool
	// The server's configuration
	Config *ServerConfig
	// Metrics are the metrics that the server tracks for API calls.
	Metrics servermetrics.Metrics
	// Operations is responsible for the server's operation information.
	Operations operationsServer
	// CA is the default certificate authority for the server.
	CA
	// metrics for database requests
	dbMetrics *db.Metrics
	// mux is used to server API requests
	mux *gmux.Router
	// listener for this server
	listener net.Listener
	// An error which occurs when serving
	serveError error
	// caMap is a list of CAs by name
	caMap map[string]*CA
	// caConfigMap is a list CA configs by filename
	caConfigMap map[string]*CAConfig
	// levels currently supported by the server
	levels *dbutil.Levels
	wait   chan bool
	mutex  sync.Mutex
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
	s.Config.Operations.Metrics = s.Config.Metrics
	s.Operations = operations.NewSystem(s.Config.Operations)
	s.initMetrics()

	serverVersion := metadata.GetVersion()
	err = calog.SetLogLevel(s.Config.LogLevel, s.Config.Debug)
	if err != nil {
		return err
	}
	log.Infof("Server Version: %s", serverVersion)
	s.levels, err = metadata.GetLevels(serverVersion)
	if err != nil {
		return err
	}
	log.Infof("Server Levels: %+v", s.levels)

	s.mux = gmux.NewRouter()
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

func (s *Server) initMetrics() {
	s.Metrics = servermetrics.Metrics{
		APICounter:  s.Operations.NewCounter(servermetrics.APICounterOpts),
		APIDuration: s.Operations.NewHistogram(servermetrics.APIDurationOpts),
	}
	s.dbMetrics = &db.Metrics{
		APICounter:  s.Operations.NewCounter(db.APICounterOpts),
		APIDuration: s.Operations.NewHistogram(db.APIDurationOpts),
	}
}

func (s *Server) startOperationsServer() error {
	err := s.Operations.Start()
	if err != nil {
		return err
	}

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

	// Start operations server
	err = s.startOperationsServer()
	if err != nil {
		return err
	}

	err = s.Operations.RegisterChecker("server", s)
	if err != nil {
		return nil
	}

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
	// Stop operations server
	err := s.Operations.Stop()
	if err != nil {
		return err
	}

	if s.listener == nil {
		return nil
	}

	_, port, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		return err
	}

	err = s.closeListener()
	if err != nil {
		return err
	}
	if s.wait == nil {
		return nil
	}

	for i := 0; i < 10; i++ {
		select {
		case <-s.wait:
			log.Debugf("Stop: successful stop on port %s", port)
			close(s.wait)
			s.wait = nil
			return nil
		default:
			log.Debugf("Stop: waiting for listener on port %s to stop", port)
			time.Sleep(time.Second)
		}
	}
	log.Debugf("Stop: timed out waiting for stop notification for port %s", port)
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
			attr.Roles:          "*",
			attr.DelegateRoles:  "*",
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
	s.CA.server = s
	s.CA.HomeDir = s.HomeDir
	err = s.initMultiCAConfig()
	if err != nil {
		return err
	}
	revoke.SetCRLFetcher(s.fetchCRL)
	// Make file names absolute
	s.makeFileNamesAbsolute()

	compModeStr := os.Getenv("FABRIC_CA_SERVER_COMPATIBILITY_MODE_V1_3")
	if compModeStr == "" {
		compModeStr = "true" // TODO: Change default to false once all clients have been updated to use the new authorization header
	}

	s.Config.CompMode1_3, err = strconv.ParseBool(compModeStr)
	if err != nil {
		return errors.WithMessage(err, "Invalid value for boolean environment variable 'FABRIC_CA_SERVER_COMPATIBILITY_MODE_V1_3'")
	}

	return nil
}

// Initialize config related to multiple CAs
func (s *Server) initMultiCAConfig() (err error) {
	cfg := s.Config
	if cfg.CAcount != 0 && len(cfg.CAfiles) > 0 {
		return errors.New("The --cacount and --cafiles options are mutually exclusive")
	}
	if cfg.CAcfg.Intermediate.ParentServer.URL != "" && cfg.CAcount > 0 {
		return errors.New("The --cacount option is not permissible for an intermediate server; use the --cafiles option instead")
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
		return nil, caerrors.NewHTTPErr(404, caerrors.ErrCANotFound, "CA '%s' does not exist", name)
	}
	return ca, nil
}

// Register all endpoint handlers
func (s *Server) registerHandlers() {
	s.mux.Use(s.cors, s.middleware)
	s.registerHandler(newCAInfoEndpoint(s))
	s.registerHandler(newRegisterEndpoint(s))
	s.registerHandler(newEnrollEndpoint(s))
	s.registerHandler(newIdemixEnrollEndpoint(s))
	s.registerHandler(newIdemixCRIEndpoint(s))
	s.registerHandler(newReenrollEndpoint(s))
	s.registerHandler(newRevokeEndpoint(s))
	s.registerHandler(newTCertEndpoint(s))
	s.registerHandler(newGenCRLEndpoint(s))
	s.registerHandler(newIdentitiesStreamingEndpoint(s))
	s.registerHandler(newIdentitiesEndpoint(s))
	s.registerHandler(newAffiliationsStreamingEndpoint(s))
	s.registerHandler(newAffiliationsEndpoint(s))
	s.registerHandler(newCertificateEndpoint(s))
}

// Register a handler
func (s *Server) registerHandler(se *serverEndpoint) {
	s.mux.Handle("/"+se.Path, se).Name(se.Path)
	s.mux.Handle(apiPathPrefix+se.Path, se).Name(se.Path)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics := httpsnoop.CaptureMetrics(next, w, r)
		apiName := s.getAPIName(r)
		caName := s.getCAName()
		s.recordMetrics(metrics.Duration, caName, apiName, strconv.Itoa(metrics.Code))
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	if s.Config.CORS.Enabled {
		return ghandlers.CORS(ghandlers.AllowedOrigins(s.Config.CORS.Origins))(next)
	}
	return next
}

func (s *Server) getAPIName(r *http.Request) string {
	var apiName string
	var match gmux.RouteMatch
	if s.mux.Match(r, &match) {
		apiName = match.Route.GetName()
	}
	return apiName
}

func (s *Server) getCAName() string {
	return s.CA.Config.CA.Name
}

func (s *Server) recordMetrics(duration time.Duration, caName, apiName, statusCode string) {
	s.Metrics.APICounter.With("ca_name", caName, "api_name", apiName, "status_code", statusCode).Add(1)
	s.Metrics.APIDuration.With("ca_name", caName, "api_name", apiName, "status_code", statusCode).Observe(duration.Seconds())
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
			log.Debugf("TLS Certificate: %s, TLS Key: %s", c.TLS.CertFile, c.TLS.KeyFile)
		} else if !util.FileExists(c.TLS.CertFile) {
			// TLS key file is not specified, generate TLS key and cert if they are not already generated
			err = s.autoGenerateTLSCertificateKey()
			if err != nil {
				return fmt.Errorf("Failed to automatically generate TLS certificate and key: %s", err)
			}
		}

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
			CipherSuites: stls.DefaultCipherSuites,
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

// HealthCheck pings the database to determine if it is reachable
func (s *Server) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
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

	if s.listener == nil {
		msg := fmt.Sprintf("Stop: listener was already closed")
		log.Debugf(msg)
		return errors.New(msg)
	}

	_, port, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		return err
	}

	err = s.listener.Close()
	if err != nil {
		log.Debugf("Stop: failed to close listener on port %s: %s", port, err)
		return err
	}

	log.Debugf("Stop: successfully closed listener on port %s", port)
	s.listener = nil

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
		return errors.Wrapf(err, "a CA already exists with the following subject distinguished name: %s", newDN.subject)
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
	distinguishedName := &DN{
		issuer:  cert.Issuer.String(),
		subject: cert.Subject.String(),
	}
	return distinguishedName, nil
}

func (s *Server) autoGenerateTLSCertificateKey() error {
	log.Debug("TLS enabled but either certificate or key file does not exist, automatically generating TLS credentials")

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
	err = ioutil.WriteFile(s.Config.TLS.CertFile, cert, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write TLS certificate: %s", err)
	}

	// If c.TLS.Keyfile is specified then print out the key file path. If key file is not provided, then key generation is
	// handled by BCCSP then only print out cert file path
	c := s.Config
	log.Debugf("Generated TLS Certificate: %s", c.TLS.CertFile)

	return nil
}

// Log is a function required to meet the interface required by statsd
func (s *Server) Log(keyvals ...interface{}) error {
	log.Warning(keyvals...)
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
