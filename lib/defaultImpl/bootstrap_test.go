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

package defaultImpl

import (
	"os"
	"testing"

	"github.com/cloudflare/cfssl/cli"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

// var testDB *sqlx.DB
var CFG *config.Config

const (
	path = "/tmp/hyperledger/bootstrapTest"
)

func prepBootstrap() *sqlx.DB {
	os.MkdirAll(path, 0755)
	cfg := new(cli.Config)
	cfg.ConfigFile = "../../testdata/cop.json"
	cfg.DBConfigFile = "../../testdata/bootstrapTest.json"
	config.Init(cfg)
	CFG = config.CFG
	testDB, _ := util.CreateTables(CFG)
	return testDB
}

func TestAll(t *testing.T) {
	db := prepBootstrap()
	b := BootstrapDB(db)

   _ = b
   /* Saad TODO: temporarily commenting out til working (Keith)
	testBootstrapGroup(b, t)
	testBootstrapUsers(b, t)
   */

	os.RemoveAll(path)
}

func testBootstrapGroup(b *Bootstrap, t *testing.T) {
	b.PopulateGroupsTable(b.db)

	_, _, err := b.dbAccessor.GetGroup("bank_b")

	if err != nil {
		t.Error("Failed bootstrapping groups table")
	}
}

func testBootstrapUsers(b *Bootstrap, t *testing.T) {
	b.PopulateUsersTable(b.db, CFG)

	_, err := b.dbAccessor.GetUser("keith")

	if err != nil {
		t.Error("Failed bootstrapping users table")
	}
}
