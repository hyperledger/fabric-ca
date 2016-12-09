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

/*
 * This file contains interfaces for the COP library.
 * COP provides police-like security functions for Hyperledger Fabric.
 */

package server

import (
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/server/dbutil"
	"github.com/hyperledger/fabric-cop/cli/server/spi"
	"github.com/jmoiron/sqlx"
)

// NewUserRegistry abstracts out the user retreival
func NewUserRegistry(typ string, config string) (spi.UserRegistry, error) {
	var db *sqlx.DB
	var err error
	var exists bool

	switch typ {
	case "sqlite3":
		db, exists, err = dbutil.NewUserRegistrySQLLite3(config)
		if err != nil {
			return nil, err
		}

	case "postgres":
		db, exists, err = dbutil.NewUserRegistryPostgres(config)
		if err != nil {
			return nil, err
		}

	case "mysql":
		db, exists, err = dbutil.NewUserRegistryMySQL(config)
		if err != nil {
			return nil, err
		}

	default:
		return nil, cop.NewError(cop.DatabaseError, "Unsupported type")
	}

	dbAccessor := new(Accessor)
	dbAccessor.SetDB(db)

	CFG.UserRegistery = dbAccessor

	if !exists {
		err := bootstrapDB()
		if err != nil {
			return nil, err
		}
	}

	return dbAccessor, nil
}
