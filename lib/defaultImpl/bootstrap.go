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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

type Bootstrap struct {
	db         *sqlx.DB
	dbAccessor *Accessor
}

func BootstrapDB(db *sqlx.DB) *Bootstrap {
	b := new(Bootstrap)
	b.db = db
	b.dbAccessor = NewAccessor(b.db)
	return b
}

func (b *Bootstrap) PopulateUsersTable(db *sqlx.DB, cfg *config.Config) error {
	log.Debug("populateUsersTable")
	for name, info := range cfg.Users {
		metaDataBytes, _ := json.Marshal(info.Attributes)

		id := name
		group := info.Group
		metadata := string(metaDataBytes)
		registrar := ""

		reg := NewRegisterUser()
		reg.RegisterUser(id, group, metadata, registrar)
	}
	return nil
}

func (b *Bootstrap) populateGroup(name, parent, key string, level int, db *sqlx.DB) {
	registerGroup(name, parent, db)
	newKey := key + "." + name

	if level == 0 {
		affiliationGroups := viper.GetStringSlice(newKey)
		for ci := range affiliationGroups {
			registerGroup(affiliationGroups[ci], name, db)
		}
	} else {
		affiliationGroups := viper.GetStringMapString(newKey)
		for childName := range affiliationGroups {
			b.populateGroup(childName, name, newKey, level-1, db)
		}
	}
}

// populateAffiliationGroupsTable populates affiliation groups table.
func (b *Bootstrap) PopulateGroupsTable(db *sqlx.DB) {
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("cop")
	viper.SetConfigType("json")
	viper.AddConfigPath("./")

	gopath := os.Getenv("GOPATH")
	for _, p := range filepath.SplitList(gopath) {
		cfgpath := filepath.Join(p, "src/github.com/hyperledger/fabric-cop")
		viper.AddConfigPath(cfgpath)
	}
	err := viper.ReadInConfig()
	if err != nil {
		log.Errorf("Fatal error when reading cop config file: %s", err)
	}

	key := "groups"
	affiliationGroups := viper.GetStringMapString(key)
	for name := range affiliationGroups {
		b.populateGroup(name, "", key, 1, db)
	}
}

func registerGroup(name string, parentName string, db *sqlx.DB) error {
	mutex.Lock()
	defer mutex.Unlock()

	log.Debug("Registering affiliation group " + name + " parent " + parentName + ".")

	dbAccessor := NewAccessor(db)

	var err error
	_, _, err = dbAccessor.GetGroup(name)
	if err == nil {
		return errors.New("User already registered")
	}

	err = dbAccessor.InsertGroup(name, parentName)
	if err != nil {
		log.Error(err)
	}

	return err

}
