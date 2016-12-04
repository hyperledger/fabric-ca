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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/viper"
)

// Bootstrap is used for bootstrapping database
type Bootstrap struct {
}

// BootstrapDB is a constructor to bootstrap the database at server startup
func BootstrapDB() *Bootstrap {
	b := new(Bootstrap)
	return b
}

// PopulateUsersTable populates the user table with the users defined in the server configuration file
func (b *Bootstrap) PopulateUsersTable() error {
	log.Debug("populateUsersTable")
	for name, info := range CFG.Users {

		reg := NewRegisterUser()
		reg.RegisterUser(name, info.Type, info.Group, info.Attributes, "", info.Pass, strconv.Itoa(CFG.UsrReg.MaxEnrollments))
	}
	return nil
}

func (b *Bootstrap) populateGroup(name, parent, key string, level int) {
	b.registerGroup(name, parent)
	newKey := key + "." + name

	if level == 0 {
		affiliationGroups := viper.GetStringSlice(newKey)
		for ci := range affiliationGroups {
			b.registerGroup(affiliationGroups[ci], name)
		}
	} else {
		affiliationGroups := viper.GetStringMapString(newKey)
		for childName := range affiliationGroups {
			b.populateGroup(childName, name, newKey, level-1)
		}
	}
}

// PopulateGroupsTable populates affiliation groups table based on the groups defined in the server configuration file
func (b *Bootstrap) PopulateGroupsTable() {
	log.Debug("PopulateGroupsTable")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	base := filepath.Base(CFG.ConfigFile)
	filename := strings.Split(base, ".")
	name := filename[0]
	typ := filename[1]

	viper.SetConfigName(name)
	viper.SetConfigType(typ)

	configPath := filepath.Dir(CFG.ConfigFile)
	viper.AddConfigPath(configPath)
	err := viper.ReadInConfig()
	if err != nil {
		log.Errorf("Fatal error when reading cop config file: %s", err)
	}

	key := "groups"
	affiliationGroups := viper.GetStringMapString(key)
	if len(affiliationGroups) == 0 {
		log.Info("No groups specified in configuration file")
	}
	for name := range affiliationGroups {
		b.populateGroup(name, "", key, 1)
	}
}

func (b *Bootstrap) registerGroup(name string, parentName string) error {
	mutex.Lock()
	defer mutex.Unlock()

	log.Debugf("Registering affiliation group (%s) with parent (%s)", name, parentName)

	var err error
	_, err = userRegistry.GetGroup(name)
	if err == nil {
		log.Error("Group already registered")
		return errors.New("Group already registered")
	}

	err = userRegistry.InsertGroup(name, parentName)
	if err != nil {
		log.Error(err)
	}

	return err

}
