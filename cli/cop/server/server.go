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
	"os"
	"path/filepath"
	"sync"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/serve"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	lib "github.com/hyperledger/fabric-cop/lib/defaultImpl"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

// Usage text of 'cfssl serve'
var serverUsageText = `cop server start -- start the COP server

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
var serverFlags = []string{"address", "port", "ca", "ca-key", "ca-bundle", "int-bundle", "int-dir", "metadata",
	"remote", "config", "responder", "responder-key", "tls-key", "tls-cert", "mutual-tls-ca", "mutual-tls-cn",
	"tls-remote-ca", "mutual-tls-client-cert", "mutual-tls-client-key", "db-config"}

var (
	mutex = &sync.RWMutex{}
)

type Server struct {
}

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
		home = "/var/hyperledger/production/.cop"
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

// ConfigureDB creates Database and Tables if they don't exist
func (s *Server) ConfigureDB(dataSource string, cfg *config.Config) error {
	log.Debug("Configure DB")
	db, err := util.GetDB(cfg.DBdriver, dataSource)
	if err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS Users (id VARCHAR(64), enrollmentId VARCHAR(100), token BLOB, metadata VARCHAR(256), state INTEGER, key BLOB)"); err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS Groups (name VARCHAR(64), parentID VARCHAR(64))"); err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE certificates (serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return err
	}

	s.BootstrapDB(db, cfg)

	return nil
}

// BootstrapDB loads the database based on config file
func (s *Server) BootstrapDB(db *sqlx.DB, cfg *config.Config) error {
	b := lib.BootstrapDB(db)
	b.PopulateGroupsTable(db)
	b.PopulateUsersTable(db, cfg)

	return nil
}

// startMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle sign, bundle, and validate requests.
func startMain(args []string, c cli.Config) error {
	log.Debug("server.startMain")

	s := new(Server)
	home, err := s.CreateHome()
	if err != nil {
		return err
	}

	config.Init(&c)
	cfg := config.CFG
	cfg.Home = home

	dataSource := filepath.Join(home, cfg.DataSource)

	if cfg.DataSource != "" {
		// Check if database exists if not create it and bootstrap it based on the config file
		if _, err := os.Stat(dataSource); err != nil {
			if os.IsNotExist(err) {
				err = s.ConfigureDB(dataSource, cfg)
				if err != nil {
					return err
				}
			}
		}
	}

	return serve.Command.Main(args, c)
}

// StartCommand assembles the definition of Command 'serve'
var StartCommand = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: startMain}
