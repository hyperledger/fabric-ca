/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	rice "github.com/GeertJohan/go.rice"
	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/api/bundle"
	"github.com/cloudflare/cfssl/api/certinfo"
	"github.com/cloudflare/cfssl/api/crl"
	"github.com/cloudflare/cfssl/api/generator"
	"github.com/cloudflare/cfssl/api/info"
	"github.com/cloudflare/cfssl/api/initca"
	apiocsp "github.com/cloudflare/cfssl/api/ocsp"
	"github.com/cloudflare/cfssl/api/scan"
	"github.com/cloudflare/cfssl/api/signhandler"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/ocspsign"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
	"github.com/cloudflare/cfssl/ubiquity"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/jmoiron/sqlx"
)

var (
	// Usage text of 'fabric-ca server start'
	serverUsageText = `fabric-ca server start -- start the fabric-ca server

Usage:
        fabric-ca server start [-address address] [-ca cert] [-ca-bundle bundle] \
                               [-ca-key key] [-int-bundle bundle] [-int-dir dir] [-port port] \
                               [-metadata file] [-remote remote_host] [-config config] \
                               [-responder cert] [-responder-key key] [-tls-cert cert] [-tls-key key] \
                               [-mutual-tls-ca ca] [-mutual-tls-cn regex] \
                               [-tls-remote-ca ca] [-mutual-tls-client-cert cert] [-mutual-tls-client-key key] \
                               [-db-config db-config]

Flags:
`

	// Flags used by 'cfssl serve'
	serverFlags = []string{"address", "port", "ca", "ca-key", "ca-bundle", "int-bundle", "int-dir", "metadata",
		"remote", "config", "responder", "responder-key", "tls-key", "tls-cert", "mutual-tls-ca", "mutual-tls-cn",
		"tls-remote-ca", "mutual-tls-client-cert", "mutual-tls-client-key", "db-config"}

	// V1APIPrefix is the prefix of all CFSSL V1 API Endpoints.
	V1APIPrefix = "/api/v1/cfssl/"
)

var (
	conf       cli.Config
	ocspSigner ocsp.Signer
	db         *sqlx.DB
	homeDir    string
	configDir  string
	configFile string
)

var (
	errBadSigner          = errors.New("signer not initialized")
	errNoCertDBConfigured = errors.New("cert db not configured (missing -db-config)")
)

const (
	sqlite = "sqlite3"
)

// Command defines the server-related commands and calls cli.Start to process args
func Command() error {
	util.SetDefaultServerPort()
	// The server commands
	cmds := map[string]*cli.Command{
		"init":  InitServerCommand,
		"start": StartCommand,
	}
	return cli.Start(cmds)
}

// Server ...
type Server struct {
	ConfigDir       string
	ConfigFile      string
	StartFromConfig bool
}

// BootstrapDB loads the database based on config file
func bootstrapDB() error {
	log.Debug("Bootstrap DB")

	b := BootstrapDB()
	b.PopulateGroupsTable()
	b.PopulateUsersTable()
	log.Debug("Completed BootstrapDB")
	return nil
}

// startMain is the command line entry point to the fabric-ca server.
// It sets up a new HTTP server to handle fabric-ca requests.
func startMain(args []string, c cli.Config) error {
	log.Debug("server.startMain")
	var err error

	configInit(&c)

	if c.CAFile == "" || c.CAKeyFile == "" {
		return errors.New("Failed to start server. No certificate/key file provided. Please specify certificate/key file via CLI or configuration file")
	}

	lib.MyCSP = factory.GetDefault()

	// Initialize the user registry
	err = InitUserRegistry(CFG)
	if err != nil {
		log.Errorf("Failed to initialize user registry: %s", err)
		return err
	}

	s := new(Server)
	return s.serverMain(args, c)
}

// serverMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle all endpoints
func (s *Server) serverMain(args []string, c cli.Config) error {
	conf = c
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	var err error

	if err = ubiquity.LoadPlatforms(conf.Metadata); err != nil {
		return err
	}

	log.Info("Initializing signer")

	if lib.EnrollSigner, err = SignerFromConfigAndDB(c, db); err != nil {
		log.Warningf("couldn't initialize signer: %v", err)
	}

	if ocspSigner, err = ocspsign.SignerFromConfig(c); err != nil {
		log.Warningf("couldn't initialize ocsp signer: %v", err)
	}

	registerHandlers()

	addr := net.JoinHostPort(conf.Address, strconv.Itoa(conf.Port))

	if !CFG.TLSDisable {
		log.Debug("TLS Enabled")

		if conf.MutualTLSCAFile != "" {
			clientPool, err := helpers.LoadPEMCertPool(conf.MutualTLSCAFile)
			if err != nil {
				return fmt.Errorf("failed to load mutual TLS CA file: %s", err)
			}

			server := http.Server{
				Addr: addr,
				TLSConfig: &tls.Config{
					ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs:  clientPool,
				},
			}

			log.Info("Now listening with mutual TLS on https://", addr)
			return server.ListenAndServeTLS(conf.TLSCertFile, conf.TLSKeyFile)
		}
		log.Info("Now listening on https://", addr)
		return http.ListenAndServeTLS(addr, conf.TLSCertFile, conf.TLSKeyFile, nil)
	}

	log.Info("Now listening on ", addr)
	return http.ListenAndServe(addr, nil)
}

// registerHandlers instantiates various handlers and associate them to corresponding endpoints.
func registerHandlers() {
	for path, getHandler := range endpoints {
		log.Debugf("getHandler for %s", path)
		if handler, err := getHandler(); err != nil {
			log.Warningf("endpoint '%s' is disabled: %v", path, err)
		} else {
			if path, handler, err = lib.NewAuthWrapper(path, handler, err); err != nil {
				log.Warningf("endpoint '%s' has been disabled: %v", path, err)
			} else {
				log.Infof("endpoint '%s' is enabled", path)
				http.Handle(path, handler)
			}
		}
	}
	log.Info("Handler set up complete.")
}

// httpBox implements http.FileSystem which allows the use of Box with a http.FileServer.
// Atempting to Open an API endpoint will result in an error.
type httpBox struct {
	*rice.Box
	redirects map[string]string
}

func (hb *httpBox) findStaticBox() (err error) {
	hb.Box, err = rice.FindBox("static")
	return
}

// Open returns a File for non-API enpoints using the http.File interface.
func (hb *httpBox) Open(name string) (http.File, error) {
	if strings.HasPrefix(name, V1APIPrefix) {
		return nil, os.ErrNotExist
	}

	if location, ok := hb.redirects[name]; ok {
		return hb.Box.Open(location)
	}

	return hb.Box.Open(name)
}

// staticBox is the box containing all static assets.
var staticBox = &httpBox{
	redirects: map[string]string{
		"/scan":   "/index.html",
		"/bundle": "/index.html",
	},
}

var endpoints = map[string]func() (http.Handler, error){

	// The following are the fabric-ca specific endpoints
	"register": NewRegisterHandler,
	"enroll":   lib.NewEnrollHandler,
	"reenroll": lib.NewReenrollHandler,
	"revoke":   lib.NewRevokeHandler,
	"tcert":    lib.NewTCertHandler,

	// The remainder are the CFSSL endpoints
	"sign": func() (http.Handler, error) {
		if lib.EnrollSigner == nil {
			return nil, errBadSigner
		}
		return signhandler.NewHandlerFromSigner(lib.EnrollSigner)
	},

	"authsign": func() (http.Handler, error) {
		if lib.EnrollSigner == nil {
			return nil, errBadSigner
		}
		return signhandler.NewAuthHandlerFromSigner(lib.EnrollSigner)
	},

	"info": func() (http.Handler, error) {
		if lib.EnrollSigner == nil {
			return nil, errBadSigner
		}
		return info.NewHandler(lib.EnrollSigner)
	},

	"gencrl": func() (http.Handler, error) {
		if lib.EnrollSigner == nil {
			return nil, errBadSigner
		}
		return crl.NewHandler(), nil
	},

	"newcert": func() (http.Handler, error) {
		if lib.EnrollSigner == nil {
			return nil, errBadSigner
		}
		h := generator.NewCertGeneratorHandlerFromSigner(generator.CSRValidate, lib.EnrollSigner)
		if conf.CABundleFile != "" && conf.IntBundleFile != "" {
			cg := h.(api.HTTPHandler).Handler.(*generator.CertGeneratorHandler)
			if err := cg.SetBundler(conf.CABundleFile, conf.IntBundleFile); err != nil {
				return nil, err
			}
		}
		return h, nil
	},

	"bundle": func() (http.Handler, error) {
		return bundle.NewHandler(conf.CABundleFile, conf.IntBundleFile)
	},

	"newkey": func() (http.Handler, error) {
		return generator.NewHandler(generator.CSRValidate)
	},

	"init_ca": func() (http.Handler, error) {
		return initca.NewHandler(), nil
	},

	"scan": func() (http.Handler, error) {
		return scan.NewHandler(conf.CABundleFile)
	},

	"scaninfo": func() (http.Handler, error) {
		return scan.NewInfoHandler(), nil
	},

	"certinfo": func() (http.Handler, error) {
		return certinfo.NewHandler(), nil
	},

	"ocspsign": func() (http.Handler, error) {
		if ocspSigner == nil {
			return nil, errBadSigner
		}
		return apiocsp.NewHandler(ocspSigner), nil
	},

	"/": func() (http.Handler, error) {
		if err := staticBox.findStaticBox(); err != nil {
			return nil, err
		}

		return http.FileServer(staticBox), nil
	},
}

// SignerFromConfigAndDB takes the Config and creates the appropriate
// signer.Signer object with a specified db
func SignerFromConfigAndDB(c cli.Config, db *sqlx.DB) (signer.Signer, error) {
	// If there is a config, use its signing policy. Otherwise create a default policy.
	var err error
	var policy *config.Signing
	if c.CFG != nil {
		policy = c.CFG.Signing
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
			log.Infof("Invalid remote %v, reverting to configuration default", c.Remote)
			return nil, err
		}
	}

	lib.EnrollSigner, err = universal.NewSigner(cli.RootFromConfig(&c), policy)
	if err != nil {
		return nil, err
	}

	if db != nil {
		certAccessor := InitCertificateAccessor(db)
		lib.EnrollSigner.SetDBAccessor(certAccessor)
	}

	return lib.EnrollSigner, nil
}

// Start will start server
// THIS IS ONLY USED FOR TEST CASE EXECUTION
func (s *Server) Start(opts ...string) error {
	log.Debug("Server starting")
	osArgs := os.Args
	config := filepath.Join(s.ConfigDir, s.ConfigFile)

	if len(opts) > 0 && opts[0] == "true" {
		os.Args = []string{"server", "start"}
	} else {
		if !s.StartFromConfig {
			cert := filepath.Join(s.ConfigDir, "ec.pem")
			key := filepath.Join(s.ConfigDir, "ec-key.pem")
			os.Args = []string{"server", "start", "-ca", cert, "-ca-key", key, "-config", config}
		} else {
			os.Args = []string{"server", "start", "-config", config}
		}
	}

	err := Command()
	if err != nil {
		return err
	}

	os.Args = osArgs
	return nil
}

// StartCommand assembles the definition of Command 'fabric-ca server start'
var StartCommand = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: startMain}
