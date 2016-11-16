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

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3" // Needed to support sqlite
)

// Config is COP config structure
type Config struct {
	Debug          bool             `json:"debug,omitempty"`
	Authentication bool             `json:"authentication,omitempty"`
	Users          map[string]*User `json:"users,omitempty"`
	DBdriver       string           `json:"driver"`
	DataSource     string           `json:"data_source"`
	Home           string
	ConfigFile     string
	CACert         string
	CAKey          string
	DB             *sqlx.DB
	DBAccessor     *Accessor
}

// User information
type User struct {
	Pass       string          `json:"pass"` // enrollment secret
	Type       string          `json:"type"`
	Group      string          `json:"group"`
	Attributes []idp.Attribute `json:"attrs,omitempty"`
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
	log.Debugf("config.Init file=%s", cfg.ConfigFile)
	CFG = newConfig()

	if cfg.CAFile != "" {
		CFG.CACert = cfg.CAFile
	}
	if cfg.CAKeyFile != "" {
		CFG.CAKey = cfg.CAKeyFile
	}
	if cfg.ConfigFile != "" {
		CFG.ConfigFile = cfg.ConfigFile
		cfg.DBConfigFile = cfg.ConfigFile
		body, err := ioutil.ReadFile(cfg.ConfigFile)
		if err != nil {
			panic(err.Error())
		}
		log.Debugf("config.Init contents=%+v", body)
		err = json.Unmarshal(body, CFG)
		if err != nil {
			panic(fmt.Sprintf("error parsing %s: %s", cfg.ConfigFile, err.Error()))
		}
	}

	dbg := os.Getenv("COP_DEBUG")
	if dbg != "" {
		CFG.Debug = dbg == "true"
	}
	if CFG.Debug {
		log.Level = log.LevelDebug
	}

}
