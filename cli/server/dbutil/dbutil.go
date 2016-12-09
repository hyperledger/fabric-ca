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

package dbutil

import (
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/jmoiron/sqlx"
)

// GetDB returns a pointer to the database
func GetDB(dbdriver string, datasource string) (*sqlx.DB, error) {
	log.Debugf("Check if database exists: %s", datasource)
	var err error
	var db *sqlx.DB

	switch dbdriver {
	case "sqlite3":
		db, _, err = NewUserRegistrySQLLite3(datasource)
	case "postgres":
		db, _, err = NewUserRegistryPostgres(datasource)
	case "mysql":
		db, _, err = NewUserRegistryMySQL(datasource)
	default:
		log.Error("Unsupported database type")
		return nil, cop.NewError(cop.DatabaseError, "Unsupported database type")
	}

	if err != nil {
		return nil, err
	}

	return db, nil
}

// NewUserRegistrySQLLite3 returns a pointer to a sqlite database
func NewUserRegistrySQLLite3(datasource string) (*sqlx.DB, bool, error) {
	log.Debugf("Using sqlite database, connect to database in home (%s) directory", datasource)
	datasource = filepath.Join(datasource)
	var exists bool

	if datasource != "" {
		// Check if database exists if not create it and bootstrap it based on the config file
		if _, err := os.Stat(datasource); err != nil {
			if os.IsNotExist(err) {
				log.Debugf("Database (%s) does not exist", datasource)
				exists = false
				err2 := createSQLiteDBTables(datasource)
				if err2 != nil {
					return nil, false, err2
				}
			} else {
				log.Debug("Database (%s) exists", datasource)
				exists = true
			}
		}
	}

	db, err := sqlx.Open("sqlite3", datasource)
	if err != nil {
		return nil, false, err
	}

	return db, exists, nil
}

func createSQLiteDBTables(datasource string) error {
	log.Debug("Creating SQLite Database...")
	log.Debug("Database location: ", datasource)
	db, err := sqlx.Open("sqlite3", datasource)
	if err != nil {
		return cop.WrapError(err, cop.DatabaseError, "Failed to connect to database")
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(64), token bytea, type VARCHAR(64), attributes VARCHAR(256), state INTEGER, serial_number bytea, authority_key_identifier bytea)"); err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS groups (name VARCHAR(64), parent_id VARCHAR(64), group_key VARCHAR(48))"); err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return err
	}

	return nil
}

// NewUserRegistryPostgres opens a connecton to a postgres database
func NewUserRegistryPostgres(datasource string) (*sqlx.DB, bool, error) {
	log.Debugf("Using postgres database, connecting to database...")

	var exists bool
	dbName := getDBName(datasource)
	log.Debug("Database Name: ", dbName)

	connStr := getConnStr(datasource)

	db, err := sqlx.Open("postgres", connStr)
	if err != nil {
		msg := "Failed to connect to database"
		log.Error(msg)
		return nil, false, cop.WrapError(err, cop.DatabaseError, msg)
	}

	// Check if database exists
	r, err2 := db.Exec("SELECT * FROM pg_catalog.pg_database where datname=$1", dbName)
	if err2 != nil {
		msg := "Failed to query 'pg_database' table"
		log.Error(msg+" error: ", err2)
		return nil, false, cop.WrapError(err, cop.DatabaseError, msg)
	}

	found, _ := r.RowsAffected()
	if found == 0 {
		log.Debugf("Database (%s) does not exist", dbName)
		exists = false
		err = createPostgresDBTables(datasource, dbName, db)
		if err != nil {
			return nil, false, err
		}
	} else {
		log.Debugf("Database (%s) exists", dbName)
		exists = true
	}

	db, err = sqlx.Open("postgres", datasource)
	if err != nil {
		return nil, false, err
	}

	return db, exists, nil
}

// createPostgresDB creates postgres database
func createPostgresDBTables(datasource string, dbName string, db *sqlx.DB) error {
	log.Debugf("Creating Postgres Database (%s)...", dbName)

	query := "CREATE DATABASE " + dbName
	_, err := db.Exec(query)
	if err != nil {
		return cop.WrapError(err, cop.DatabaseError, "Failed to create Postgres database")
	}

	database, err := sqlx.Open("postgres", datasource)
	if err != nil {
		log.Errorf("Failed to open database (%s)", dbName)
	}

	log.Debug("Create Tables...")
	if _, err := database.Exec("CREATE TABLE users (id VARCHAR(64), token bytea, type VARCHAR(64), attributes VARCHAR(256), state INTEGER, serial_number bytea, authority_key_identifier bytea)"); err != nil {
		log.Errorf("Error creating users table [error: %s] ", err)

		return err
	}
	if _, err := database.Exec("CREATE TABLE groups (name VARCHAR(64), parent_id VARCHAR(64), group_key VARCHAR(48))"); err != nil {
		log.Errorf("Error creating groups table [error: %s] ", err)
		return err
	}
	if _, err := database.Exec("CREATE TABLE certificates (serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		log.Errorf("Error creating certificates table [error: %s] ", err)
		return err
	}
	return nil
}

// NewUserRegistryMySQL opens a connecton to a postgres database
func NewUserRegistryMySQL(datasource string) (*sqlx.DB, bool, error) {
	log.Debugf("Using MySQL database, connecting to database...")

	var exists bool
	dbName := getDBName(datasource)
	connStr := strings.Split(datasource, "/")[0] + "/"

	db, err := sqlx.Open("mysql", connStr)
	if err != nil {
		msg := "Failed to open to database"
		log.Error(msg+" error: ", err)
		return nil, false, cop.WrapError(err, cop.DatabaseError, msg)
	}

	// Check if database exists
	// r, err2 := db.Exec("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?", dbName)
	var name string
	err = db.QueryRow("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?", dbName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debugf("Database (%s) does not exist", dbName)
			exists = false
		} else {
			msg := "Failed to query 'INFORMATION_SCHEMA.SCHEMATA' table"
			log.Error(msg+" error: ", err)
			return nil, false, cop.WrapError(err, cop.DatabaseError, "Failed to query 'INFORMATION_SCHEMA.SCHEMATA table")
		}
	}

	if name == "" {
		createMySQLTables(datasource, dbName, db)
	} else {
		log.Debugf("Database (%s) exists", dbName)
		exists = true
	}

	db, err = sqlx.Open("mysql", datasource)
	if err != nil {
		return nil, false, err
	}

	return db, exists, nil
}

func createMySQLTables(datasource string, dbName string, db *sqlx.DB) error {
	log.Debugf("Creating MySQL Database (%s)...", dbName)

	_, err := db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		panic(err)
	}

	database, err := sqlx.Open("mysql", datasource)
	if err != nil {
		log.Errorf("Failed to open database (%s), err: %s", dbName, err)
	}
	log.Debug("Create Tables...")
	if _, err := database.Exec("CREATE TABLE users (id VARCHAR(64) NOT NULL, token blob, type VARCHAR(64), attributes VARCHAR(256), state INTEGER, serial_number varbinary(20), authority_key_identifier varbinary(128), PRIMARY KEY (id))"); err != nil {
		log.Errorf("Error creating users table [error: %s] ", err)
		return err
	}
	if _, err := database.Exec("CREATE TABLE groups (name VARCHAR(64), parent_id VARCHAR(64), group_key VARCHAR(48))"); err != nil {
		log.Errorf("Error creating groups table [error: %s] ", err)
		return err
	}
	if _, err := database.Exec("CREATE TABLE certificates (serial_number varbinary(20) NOT NULL, authority_key_identifier varbinary(128) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT '1970-01-01 00:00:01', revoked_at timestamp DEFAULT '1970-01-01 00:00:01', pem varbinary(4096) NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		log.Errorf("Error creating certificates table [error: %s] ", err)
		return err
	}

	return nil
}

// GetDBName gets database name from connection string
func getDBName(datasource string) string {
	var dbName string
	datasource = strings.ToLower(datasource)

	re := regexp.MustCompile(`(?:\/([^\/?]+))|(?:dbname=([^\s]+))`)
	getName := re.FindStringSubmatch(datasource)
	if getName != nil {
		dbName = getName[1]
		if dbName == "" {
			dbName = getName[2]
		}
	}

	return dbName
}

// GetConnStr gets connection string without database
func getConnStr(datasource string) string {
	re := regexp.MustCompile(`(dbname=)([^\s]+)`)
	connStr := re.ReplaceAllString(datasource, "")
	return connStr
}
