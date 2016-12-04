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
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

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
	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/ocspsign"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
	"github.com/cloudflare/cfssl/ubiquity"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/server/dbutil"
	"github.com/jmoiron/sqlx"
)

var (
	// Usage text of 'cop server start'
	serverUsageText = `cop server start -- start the COP server

Usage:
        cop server start [-address address] [-ca cert] [-ca-bundle bundle] \
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
	s          signer.Signer
	ocspSigner ocsp.Signer
	db         *sqlx.DB
	mutex      = &sync.RWMutex{}
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
	// The server commands
	cmds := map[string]*cli.Command{
		"init":  InitServerCommand,
		"start": StartCommand,
	}
	return cli.Start(cmds)
}

// Server ...
type Server struct {
}

// CreateHome will create a home directory if it does not exist
func (s *Server) CreateHome() (string, error) {
	log.Debug("CreateHome")
	home := os.Getenv("COP_HOME")
	if home == "" {
		home = os.Getenv("HOME")
		if home != "" {
			home = home + "/.cop"
		}
	}
	if home == "" {
		home = "/var/hyperledger/fabric/dev/.fabric-cop"
	}
	if _, err := os.Stat(home); err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(home, 0755)
			if err != nil {
				return "", err
			}
		}
	}

	return home, nil
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

// startMain is the command line entry point to the COP server.
// It sets up a new HTTP server to handle COP requests.
func startMain(args []string, c cli.Config) error {
	log.Debug("server.startMain")

	s := new(Server)
	home, err := s.CreateHome()
	if err != nil {
		return err
	}
	configInit(&c)
	cfg := CFG
	cfg.Home = home

	if cfg.DataSource == "" {
		msg := "No database specified, a database is needed to run COP server. Using default - Type: SQLite, Name: cop.db"
		log.Info(msg)
		cfg.DBdriver = sqlite
		cfg.DataSource = "cop.db"
	}

	if cfg.DBdriver == sqlite {
		cfg.DataSource = filepath.Join(cfg.Home, cfg.DataSource)
	}

	// Initialize the user registry
	err = InitUserRegistry(cfg)
	if err != nil {
		return err
	}

	db, err = dbutil.GetDB(cfg.DBdriver, cfg.DataSource)
	if err != nil {
		log.Errorf("Failed to find database")
	}

	var cfsslCfg cli.Config
	cfsslCfg.CAFile = cfg.CACert
	cfsslCfg.CAKeyFile = cfg.CAKey
	mySigner, err := SignerFromConfigAndDB(cfsslCfg, db)
	if err != nil {
		log.Errorf("SignerFromConfigAndDB error: %s", err)
		return cop.WrapError(err, cop.CFSSL, "failed in SignerFromConfigAndDB")
	}
	cfg.Signer = mySigner

	return serverMain(args, c)
}

// serverMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle all endpoints
func serverMain(args []string, c cli.Config) error {
	conf = c
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	bundler.IntermediateStash = conf.IntDir
	var err error

	if err = ubiquity.LoadPlatforms(conf.Metadata); err != nil {
		return err
	}

	log.Info("Initializing signer")

	if ocspSigner, err = ocspsign.SignerFromConfig(c); err != nil {
		log.Warningf("couldn't initialize ocsp signer: %v", err)
	}

	registerHandlers()

	addr := net.JoinHostPort(conf.Address, strconv.Itoa(conf.Port))

	if conf.TLSCertFile == "" || conf.TLSKeyFile == "" {
		log.Info("Now listening on ", addr)
		return http.ListenAndServe(addr, nil)
	}

	// TODO: Temporarly commenting out as TLS is currently not supported. Will be uncommented when TLS support has been implemented

	// if conf.MutualTLSCAFile != "" {
	// 	clientPool, err := helpers.LoadPEMCertPool(conf.MutualTLSCAFile)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to load mutual TLS CA file: %s", err)
	// 	}
	//
	// 	server := http.Server{
	// 		Addr: addr,
	// 		TLSConfig: &tls.Config{
	// 			ClientAuth: tls.RequireAndVerifyClientCert,
	// 			ClientCAs:  clientPool,
	// 		},
	// 	}
	//
	// 	if conf.MutualTLSCNRegex != "" {
	// 		log.Debugf(`Requiring CN matches regex "%s" for client connections`, conf.MutualTLSCNRegex)
	// 		re, err := regexp.Compile(conf.MutualTLSCNRegex)
	// 		if err != nil {
	// 			return fmt.Errorf("malformed CN regex: %s", err)
	// 		}
	// 		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 			if r != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
	// 				if re.MatchString(r.TLS.PeerCertificates[0].Subject.CommonName) {
	// 					http.DefaultServeMux.ServeHTTP(w, r)
	// 					return
	// 				}
	// 				log.Warningf(`Rejected client cert CN "%s" does not match regex %s`,
	// 					r.TLS.PeerCertificates[0].Subject.CommonName, conf.MutualTLSCNRegex)
	// 			}
	// 			http.Error(w, "Invalid CN", http.StatusForbidden)
	// 		})
	// 	}
	// 	log.Info("Now listening with mutual TLS on https://", addr)
	// 	return server.ListenAndServeTLS(conf.TLSCertFile, conf.TLSKeyFile)
	// }
	// log.Info("Now listening on https://", addr)
	// return http.ListenAndServeTLS(addr, conf.TLSCertFile, conf.TLSKeyFile, nil)
	return nil
}

// registerHandlers instantiates various handlers and associate them to corresponding endpoints.
func registerHandlers() {
	for path, getHandler := range endpoints {
		log.Debugf("getHandler for %s", path)
		if handler, err := getHandler(); err != nil {
			log.Warningf("endpoint '%s' is disabled: %v", path, err)
		} else {
			if path, handler, err = NewAuthWrapper(path, handler, err); err != nil {
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

	// The following are the COP-specific endpoints
	"register": NewRegisterHandler,
	"enroll":   NewEnrollHandler,
	"reenroll": NewReenrollHandler,
	"revoke":   NewRevokeHandler,

	// The remainder are the CFSSL endpoints
	"sign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return signhandler.NewHandlerFromSigner(s)
	},

	"authsign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return signhandler.NewAuthHandlerFromSigner(s)
	},

	"info": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return info.NewHandler(s)
	},

	"gencrl": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return crl.NewHandler(), nil
	},

	"newcert": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		h := generator.NewCertGeneratorHandlerFromSigner(generator.CSRValidate, s)
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
	var policy *config.Signing
	if c.CFG != nil {
		policy = c.CFG.Signing
	} else {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		}
	}

	// TODO: Temporarly commenting out as TLS is currently not supported. Will be uncommented when TLS support has been implemented

	// Make sure the policy reflects the new remote
	// if c.Remote != "" {
	// 	err := policy.OverrideRemotes(c.Remote)
	// 	if err != nil {
	// 		log.Infof("Invalid remote %v, reverting to configuration default", c.Remote)
	// 		return nil, err
	// 	}
	// }
	//
	// if c.MutualTLSCertFile != "" && c.MutualTLSKeyFile != "" {
	// 	err := policy.SetClientCertKeyPairFromFile(c.MutualTLSCertFile, c.MutualTLSKeyFile)
	// 	if err != nil {
	// 		log.Infof("Invalid mutual-tls-cert: %s or mutual-tls-key: %s, defaulting to no client auth", c.MutualTLSCertFile, c.MutualTLSKeyFile)
	// 		return nil, err
	// 	}
	// 	log.Infof("Using client auth with mutual-tls-cert: %s and mutual-tls-key: %s", c.MutualTLSCertFile, c.MutualTLSKeyFile)
	// }
	//
	// if c.TLSRemoteCAs != "" {
	// 	err := policy.SetRemoteCAsFromFile(c.TLSRemoteCAs)
	// 	if err != nil {
	// 		log.Infof("Invalid tls-remote-ca: %s, defaulting to system trust store", c.TLSRemoteCAs)
	// 		return nil, err
	// 	}
	// 	log.Infof("Using trusted CA from tls-remote-ca: %s", c.TLSRemoteCAs)
	// }

	s, err := universal.NewSigner(cli.RootFromConfig(&c), policy)
	if err != nil {
		return nil, err
	}

	if db != nil {
		certAccessor := CertificateAccessor(db)
		s.SetDBAccessor(certAccessor)
	}

	return s, nil
}

// Start will start server
// THIS IS ONLY USED FOR TEST CASE EXECUTION
func Start(dir string) {
	log.Debug("Server starting")
	osArgs := os.Args
	cert := filepath.Join(dir, "ec.pem")
	key := filepath.Join(dir, "ec-key.pem")
	config := filepath.Join(dir, "testconfig.json")
	os.Args = []string{"server", "start", "-ca", cert, "-ca-key", key, "-config", config}
	Command()
	os.Args = osArgs
}

// StartCommand assembles the definition of Command 'cop server start'
var StartCommand = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: startMain}
