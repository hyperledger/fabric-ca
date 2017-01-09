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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/server/ldap"
	"github.com/hyperledger/fabric-cop/lib/tls"
	"github.com/hyperledger/fabric-cop/util"

	_ "github.com/mattn/go-sqlite3" // Needed to support sqlite
)

// Config is COP config structure
type Config struct {
	Debug          bool             `json:"debug,omitempty"`
	Authentication bool             `json:"authentication,omitempty"`
	Users          map[string]*User `json:"users,omitempty"`
	DBdriver       string           `json:"driver"`
	DataSource     string           `json:"data_source"`
	UsrReg         UserReg          `json:"user_registry"`
	LDAP           *ldap.Config     `json:"ldap,omitempty"`
	CAFile         string           `json:"ca_cert"`
	KeyFile        string           `json:"ca_key"`
	TLSConf        TLSConfig        `json:"tls,omitempty"`
	TLSDisable     bool             `json:"tls_disable,omitempty"`
}

// UserReg defines the user registry properties
type UserReg struct {
	MaxEnrollments int `json:"max_enrollments"`
}

// TLSConfig defines the files needed for a TLS connection
type TLSConfig struct {
	TLSCertFile     string              `json:"tls_cert,omitempty"`
	TLSKeyFile      string              `json:"tls_key,omitempty"`
	MutualTLSCAFile string              `json:"mutual_tls_ca,omitempty"`
	DBClient        tls.ClientTLSConfig `json:"db_client,omitempty"`
}

// User information
type User struct {
	Pass       string          `json:"pass"` // enrollment secret
	Type       string          `json:"type"`
	Group      string          `json:"group"`
	Attributes []api.Attribute `json:"attrs,omitempty"`
}

// Constructor for COP config
func newConfig() *Config {
	c := new(Config)
	c.Authentication = true
	return c
}

// CFG is the COP-specific config
var CFG *Config

// Init initializes the COP config given the CFSSL config
func configInit(cfg *cli.Config) {
	var err error
	configFile, err = filepath.Abs(cfg.ConfigFile)
	if err != nil {
		panic(err.Error())
	}
	configDir = filepath.Dir(configFile)
	log.Debugf("Initializing config file at %s", configFile)
	log.Debugf("Inbound CFSSL server config is: %+v", cfg)

	CFG = new(Config)
	CFG.Authentication = true

	body, err := ioutil.ReadFile(configFile)
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(body, CFG)
	if err != nil {
		panic(fmt.Sprintf("error parsing %s: %s", configFile, err.Error()))
	}

	CFG.CAFile = abs(CFG.CAFile)
	CFG.KeyFile = abs(CFG.KeyFile)
	CFG.TLSConf.TLSCertFile = abs(CFG.TLSConf.TLSCertFile)
	CFG.TLSConf.TLSKeyFile = abs(CFG.TLSConf.TLSKeyFile)
	CFG.TLSConf.MutualTLSCAFile = abs(CFG.TLSConf.MutualTLSCAFile)
	absTLSClient(&CFG.TLSConf.DBClient)

	if cfg.DBConfigFile == "" {
		cfg.DBConfigFile = cfg.ConfigFile
	}

	if CFG.TLSConf.TLSCertFile != "" {
		cfg.TLSCertFile = CFG.TLSConf.TLSCertFile
	} else {
		cfg.TLSCertFile = CFG.CAFile
	}

	if CFG.TLSConf.TLSKeyFile != "" {
		cfg.TLSKeyFile = CFG.TLSConf.TLSKeyFile
	} else {
		cfg.TLSKeyFile = CFG.KeyFile
	}

	if CFG.TLSConf.MutualTLSCAFile != "" {
		cfg.MutualTLSCAFile = CFG.TLSConf.MutualTLSCAFile
	}

	if CFG.DBdriver == "" {
		msg := "No database specified, a database is needed to run COP server. Using default - Type: SQLite, Name: cop.db"
		log.Info(msg)
		CFG.DBdriver = sqlite
		CFG.DataSource = "cop.db"
	}

	if CFG.DBdriver == sqlite {
		CFG.DataSource = abs(CFG.DataSource)
	}

	dbg := os.Getenv("COP_DEBUG")
	if dbg != "" {
		CFG.Debug = dbg == "true"
	}
	if CFG.Debug {
		log.Level = log.LevelDebug
	}

	log.Debugf("CFSSL server config is: %+v", cfg)
	log.Debugf("COP server config is: %+v", CFG)
}

// Make TLS client files absolute
func absTLSClient(cfg *tls.ClientTLSConfig) {
	for i := 0; i < len(cfg.CACertFiles); i++ {
		cfg.CACertFiles[i] = abs(cfg.CACertFiles[i])
	}
	cfg.Client.CertFile = abs(cfg.Client.CertFile)
	cfg.Client.KeyFile = abs(cfg.Client.KeyFile)
}

// Make 'file' absolute relative to the configuration directory
func abs(file string) string {
	path, err := util.MakeFileAbs(file, configDir)
	if err != nil {
		panic(err)
	}
	return path
}
