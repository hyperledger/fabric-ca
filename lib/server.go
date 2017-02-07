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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
	"github.com/hyperledger/fabric-ca/cli/server/dbutil"
	"github.com/hyperledger/fabric-ca/cli/server/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/jmoiron/sqlx"

	_ "github.com/go-sql-driver/mysql" // import to support MySQL
	_ "github.com/lib/pq"              // import to support Postgres
	_ "github.com/mattn/go-sqlite3"    // import to support SQLite3
)

// Server is the fabric-ca server
type Server struct {
	// The home directory for the server
	HomeDir string
	// The server's configuration
	Config *ServerConfig
	// The database handle used to store certificates and optionally
	// the user registry information, unless LDAP it enabled for the
	// user registry function.
	db *sqlx.DB
	// The user registry
	registry spi.UserRegistry
	// The signer used for enrollment
	enrollSigner signer.Signer
	// The server mux
	mux *http.ServeMux
	// The current listener for this server
	listener net.Listener
}

// Init initializes a fabric-ca server
func (s *Server) Init(renew bool) (err error) {
	// Sanity check config
	if s.Config == nil {
		return errors.New("fabric-ca-server's config is nil")
	}
	// Init home directory if not set
	if s.HomeDir == "" {
		s.HomeDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("Failed to initialize server's home directory: %s", err)
		}
	}
	// Initialize key materials
	err = s.initKeyMaterial(renew)
	if err != nil {
		return err
	}
	// Initialize the database
	err = s.initDB()
	if err != nil {
		return err
	}
	// Initialize the enrollment signer
	err = s.initEnrollmentSigner()
	if err != nil {
		return err
	}
	// Successful initialization
	return nil
}

// Start the fabric-ca server
func (s *Server) Start() error {

	var err error

	if s.listener != nil {
		return errors.New("server is already started")
	}

	// Initialize the server
	err = s.Init(false)
	if err != nil {
		return err
	}

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

// Initialize the fabric-ca server's key material
func (s *Server) initKeyMaterial(renew bool) error {
	log.Debugf("Init with home %s and config %+v", s.HomeDir, s.Config)

	// Make the path names absolute in the config
	s.makeFileNamesAbsolute()

	keyFile := s.Config.CA.Keyfile
	certFile := s.Config.CA.Certfile

	// If we aren't renewing and the key and cert files exist, do nothing
	if !renew {
		// If they both exist, the server was already initialized
		keyFileExists := util.FileExists(keyFile)
		certFileExists := util.FileExists(certFile)
		if keyFileExists && certFileExists {
			log.Info("The CA key and certificate files already exist")
			log.Infof("Key file location: %s", keyFile)
			log.Infof("Certificate file location: %s", certFile)
			return nil
		}
	}

	// Create the certificate request, copying from config
	ptr := &s.Config.CSR
	req := csr.CertificateRequest{
		CN:    ptr.CN,
		Names: ptr.Names,
		Hosts: ptr.Hosts,
		// FIXME: NewBasicKeyRequest only does ecdsa 256; use config
		KeyRequest:   csr.NewBasicKeyRequest(),
		CA:           ptr.CA,
		SerialNumber: ptr.SerialNumber,
	}

	// Initialize the CA now
	cert, _, key, err := initca.New(&req)
	if err != nil {
		return fmt.Errorf("Failed to initialize CA [%s]\nRequest was %#v", err, req)
	}

	// Store the key and certificate to file
	err = writeFile(keyFile, key, 0600)
	if err != nil {
		return fmt.Errorf("Failed to store key: %s", err)
	}
	err = writeFile(certFile, cert, 0644)
	if err != nil {
		return fmt.Errorf("Failed to store certificate: %s", err)
	}
	log.Info("The CA key and certificate files were generated")
	log.Infof("Key file location: %s", keyFile)
	log.Infof("Certificate file location: %s", certFile)
	return nil
}

// Initialize the database for the server
func (s *Server) initDB() error {
	db := &s.Config.DB

	log.Debug("Initializing database")

	var err error
	var exists bool

	if db.Type == "" {
		db.Type = "sqlite3"
	}
	if db.Datasource == "" {
		var ds string
		ds, err = util.MakeFileAbs("fabric-ca-server.db", s.HomeDir)
		if err != nil {
			return err
		}
		db.Datasource = ds
	}

	log.Debugf("Database type is '%s' and data source is '%s'", db.Type, db.Datasource)

	switch db.Type {
	case "sqlite3":
		s.db, exists, err = dbutil.NewUserRegistrySQLLite3(db.Datasource)
		if err != nil {
			return err
		}
	case "postgres":
		s.db, exists, err = dbutil.NewUserRegistryPostgres(db.Datasource, &db.TLS)
		if err != nil {
			return err
		}
	case "mysql":
		s.db, exists, err = dbutil.NewUserRegistryMySQL(db.Datasource, &db.TLS)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Invalid db.type in config file: '%s'; must be 'sqlite3', 'postgres', or 'mysql'", db.Type)
	}

	log.Infof("Initialized %s data base at %s; exists: %v", db.Type, db.Datasource, exists)
	return nil
}

// Initialize the enrollment signer
func (s *Server) initEnrollmentSigner() (err error) {

	c := s.Config

	// If there is a config, use its signing policy. Otherwise create a default policy.
	var policy *config.Signing
	if c.Signing != nil {
		policy = c.Signing
	} else {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	// Make sure the policy reflects the new remote
	if c.Remote != "" {
		err = policy.OverrideRemotes(c.Remote)
		if err != nil {
			return fmt.Errorf("Failed initializing enrollment signer: %s", err)
		}
	}

	// Get CFSSL's universal root and signer
	root := universal.Root{
		Config: map[string]string{
			"cert-file": c.CA.Certfile,
			"key-file":  c.CA.Keyfile,
		},
		ForceRemote: c.Remote != "",
	}
	s.enrollSigner, err = universal.NewSigner(root, policy)
	if err != nil {
		return err
	}
	//s.enrollSigner.SetDBAccessor(InitCertificateAccessor(s.db))

	// Successful enrollment
	return nil
}

// Starting listening and serving
func (s *Server) listenAndServe() (err error) {

	var listener net.Listener

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
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		listener, err = tls.Listen("tcp", addr, config)
		if err != nil {
			return fmt.Errorf("TLS listen failed: %s", err)
		}
		log.Infof("Listening on https://%s", addr)
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen failed: %s", err)
		}
		log.Infof("Listening on http://%s", addr)
	}
	s.listener = listener
	go s.serve()
	return nil
}

func (s *Server) serve() {
	err := http.Serve(s.listener, s.mux)
	log.Errorf("Server has stopped serving: %s", err)
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}
}

// Make all file names in the config absolute
func (s *Server) makeFileNamesAbsolute() error {
	fields := []*string{
		&s.Config.CA.Certfile,
		&s.Config.CA.Keyfile,
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

func writeFile(file string, buf []byte, perm os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(file), perm)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, buf, perm)
}
