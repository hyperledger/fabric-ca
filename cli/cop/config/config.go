package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"

	_ "github.com/mattn/go-sqlite3"
)

// Config is COP config structure
type Config struct {
	Debug          bool             `json:"debug,omitempty"`
	Authentication bool             `json:"authentication,omitempty"`
	Users          map[string]*User `json:"users,omitempty"`
	DBdriver       string           `json:"driver"`
	DataSource     string           `json:"data_source"`
	Home           string
}

// User information
type User struct {
	Pass       string          `json:"pass"` // enrollment secret
	Group      string          `json:"group"`
	Attributes []cop.Attribute `json:"attrs,omitempty"`
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
func Init(cfg *cli.Config) {
	log.Debugf("config.Init file=%s", cfg.ConfigFile)
	CFG = newConfig()
	if cfg.ConfigFile != "" {
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

	if cfg.DBConfigFile != "" {
		body, err := ioutil.ReadFile(cfg.DBConfigFile)
		if err != nil {
			panic(err.Error())
		}
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
