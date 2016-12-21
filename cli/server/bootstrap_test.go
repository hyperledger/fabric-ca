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
	"testing"

	"github.com/cloudflare/cfssl/cli"
)

// var testDB *sqlx.DB
var bootCFG *Config

const (
	bootPath = "/tmp/bootstraptest"
)

func prepBootstrap() error {
	if _, err := os.Stat(bootPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(bootPath, 0755)
		}
	} else {
		os.RemoveAll(bootPath)
		os.MkdirAll(bootPath, 0755)
	}
	var err error

	cfg := new(cli.Config)
	cfg.ConfigFile = "../../testdata/testconfig.json"
	configInit(cfg)

	bootCFG = CFG
	home = bootPath
	bootCFG.DBdriver = "sqlite3"
	datasource := filepath.Join(home, "cop.db")
	bootCFG.DataSource = datasource

	err = InitUserRegistry(bootCFG)

	if err != nil {
		return err
	}

	return nil
}

func TestAllBootstrap(t *testing.T) {
	err := prepBootstrap()
	if err != nil {
		t.Fatal("Failed to open connection to database")
	}

	testBootstrapGroup(t)
	testBootstrapUsers(t)

	os.RemoveAll(bootPath)
}

func testBootstrapGroup(t *testing.T) {
	_, err := userRegistry.GetGroup("bank_b")

	if err != nil {
		t.Error("Failed bootstrapping groups table")
	}
}

func testBootstrapUsers(t *testing.T) {
	_, err := userRegistry.GetUser("admin")

	if err != nil {
		t.Error("Failed bootstrapping users table")
	}
}
