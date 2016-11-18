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

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/util"
	"github.com/jmoiron/sqlx"
)

// GetDB returns a pointer to the database
func GetDB(cfg *Config) (*sqlx.DB, error) {
	log.Debugf("Check if database exists: %s", cfg.DataSource)
	var err error
	var db *sqlx.DB

	switch cfg.DBdriver {
	case "sqlite3":
		db, err = sqlitedb(cfg)
	case "postgres":
		db, err = postgres(cfg)
		// More cases to be added
	default:
		log.Error("Unsupported database type")
		return nil, cop.NewError(cop.DatabaseError, "Unsupported database type")
	}

	if err != nil {
		return nil, err
	}

	return db, nil
}

// sqlitedb returns a pointer to a sqlite database
func sqlitedb(cfg *Config) (*sqlx.DB, error) {
	log.Debugf("Using sqlite database, connect to database in home (%s) directory", cfg.Home)
	dataSource := filepath.Join(cfg.Home, cfg.DataSource)

	if dataSource != "" {
		// Check if database exists if not create it and bootstrap it based on the config file
		if _, err := os.Stat(dataSource); err != nil {
			if os.IsNotExist(err) {
				log.Debug("Database not found")
				err := createSQLiteDBTables(dataSource)
				if err != nil {
					return nil, err
				}

			}
		}
	}

	db, err := sqlx.Open("sqlite3", dataSource)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func createSQLiteDBTables(dataSource string) error {
	log.Debug("Creating SQLite Database...")
	log.Debug("Database location: ", dataSource)
	db, err := sqlx.Open("sqlite3", dataSource)
	if err != nil {
		return cop.WrapError(err, cop.DatabaseError, "Failed to connect to database")
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(64), enrollment_id VARCHAR(100), token BLOB, type VARCHAR(64), metadata VARCHAR(256), state INTEGER, serial_number bytea)"); err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS groups (name VARCHAR(64), parent_id VARCHAR(64))"); err != nil {
		return err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return err
	}

	return nil
}

// Postgres checks if Postgres database exists
func postgres(cfg *Config) (*sqlx.DB, error) {
	log.Debugf("Using postgres database, connecting to database...")

	dbName := util.GetDBName(cfg.DataSource)
	log.Debug("Database Name: ", dbName)

	connStr := util.GetConnStr(cfg.DataSource)

	db, err := sqlx.Open("postgres", connStr)
	if err != nil {
		msg := "Failed to open database"
		log.Error(msg)
		return nil, cop.WrapError(err, cop.DatabaseError, msg)
	}

	err = db.Ping()
	if err != nil {
		log.Error("Failed to connect to database")
		return nil, cop.WrapError(err, cop.DatabaseError, "Failed to connect to database")
	}

	// Check if database exists
	r, err2 := db.Exec("SELECT * FROM pg_catalog.pg_database where datname=$1", dbName)
	if err2 != nil {
		msg := "Failed to query 'pg_database' table"
		log.Error(msg)
		return nil, cop.WrapError(err, cop.DatabaseError, "Failed to query 'pg_database' table")
	}

	found, _ := r.RowsAffected()
	if found == 0 {
		log.Debug("Database not found")
		err = createPostgresDBTables(cfg.DataSource, dbName, db)
		if err != nil {
			return nil, err
		}
	}

	db, err = sqlx.Open("postgres", cfg.DataSource)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// createPostgresDB creates postgres database
func createPostgresDBTables(dataSource string, dbName string, db *sqlx.DB) error {
	log.Debugf("Creating Postgres Database (%s)...", dbName)

	query := "CREATE DATABASE " + dbName
	_, err := db.Exec(query)
	if err != nil {
		return cop.WrapError(err, cop.DatabaseError, "Failed to create Postgres database")
	}

	database, err := sqlx.Open("postgres", dataSource)
	if err != nil {
		log.Errorf("Failed to open database (%s)", dbName)
	}

	log.Debug("Create Tables...")
	if _, err := database.Exec("CREATE TABLE users (id VARCHAR(64), enrollment_id VARCHAR(100), token bytea, type VARCHAR(64), metadata VARCHAR(256), state INTEGER, serial_number bytea)"); err != nil {
		return err
	}
	if _, err := database.Exec("CREATE TABLE groups (name VARCHAR(64), parent_id VARCHAR(64))"); err != nil {
		return err
	}
	if _, err := database.Exec("CREATE TABLE certificates (serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return err
	}
	return nil
}
