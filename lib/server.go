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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"

	_ "github.com/go-sql-driver/mysql" // import to support MySQL
	_ "github.com/lib/pq"              // import to support Postgres
	_ "github.com/mattn/go-sqlite3"    // import to support SQLite3
)

const (
	defaultClientAuth = "noclientcert"
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
	// The parent server URL, which is non-null if this is an intermediate server
	ParentServerURL string
	// The server mux
	mux *http.ServeMux
	// The current listener for this server
	listener net.Listener
	// An error which occurs when serving
	serveError error
	// Server's default CA
	CA
}

// Init initializes a fabric-ca server
func (s *Server) Init(renew bool) (err error) {
	// Initialize the config, setting defaults, etc
	err = s.initConfig()
	if err != nil {
		return err
	}

	err = s.initCA(&s.CA, renew)
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
	err = s.Init(false)
	if err != nil {
		return err
	}

	// Register http handlers
	s.registerHandlers()

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
	id := ServerConfigIdentity{
		Name:           user,
		Pass:           pass,
		Type:           "user",
		Affiliation:    affiliation,
		MaxEnrollments: s.Config.Registry.MaxEnrollments,
		Attrs: map[string]string{
			"hf.Registrar.Roles":         "client,user,peer,validator,auditor",
			"hf.Registrar.DelegateRoles": "client,user,validator,auditor",
			"hf.Revoker":                 "true",
			"hf.IntermediateCA":          "true",
		},
	}
	registry := &s.Config.Registry
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
			return fmt.Errorf("Failed to initialize server's home directory: %s", err)
		}
	}
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

	return nil
}

func (s *Server) initCA(ca *CA, renew bool) error {
	err := initCA(ca, s.HomeDir, s.ParentServerURL, s.Config, renew)
	if err != nil {
		return err
	}

	if s.CA.Config.CA.Name == "" {
		s.CA.Config.CA.Name = DefaultCAName
	}

	return nil
}

// Register all endpoint handlers
func (s *Server) registerHandlers() {
	s.mux = http.NewServeMux()
	s.registerHandler("info", newInfoHandler, noAuth)
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
