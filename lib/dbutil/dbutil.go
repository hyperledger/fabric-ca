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
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/go-sql-driver/mysql"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/jmoiron/sqlx"
)

var (
	dbURLRegex = regexp.MustCompile("(Datasource:\\s*)?(\\S+):(\\S+)@|(Datasource:.*\\s)?(user=\\S+).*\\s(password=\\S+)|(Datasource:.*\\s)?(password=\\S+).*\\s(user=\\S+)")
)

// NewUserRegistrySQLLite3 returns a pointer to a sqlite database
func NewUserRegistrySQLLite3(datasource string) (*sqlx.DB, error) {
	log.Debugf("Using sqlite database, connect to database in home (%s) directory", datasource)

	err := createSQLiteDBTables(datasource)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to create SQLite3 database")
	}

	db, err := sqlx.Open("sqlite3", datasource+"?_busy_timeout=5000")
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open sqlite3 DB")
	}

	// Set maximum open connections to one. This is to share one connection
	// across multiple go routines. This will serialize database operations
	// with in a single server there by preventing "database is locked"
	// error under load. The "Database is locked" error is still expected
	// when multiple servers are accessing the same database (but mitigated
	// by specifying _busy_timeout to 5 seconds). Since sqlite is
	// for development and test purposes only, and is not recommended to
	// be used in a clustered topology, setting max open connections to
	// 1 is a quick and effective solution
	// For more info refer to https://github.com/mattn/go-sqlite3/issues/274
	db.SetMaxOpenConns(1)
	log.Debug("Successfully opened sqlite3 DB")

	return db, nil
}

func createSQLiteDBTables(datasource string) error {
	log.Debug("Creating SQLite database (%s) if it does not exist...", datasource)
	db, err := sqlx.Open("sqlite3", datasource)
	if err != nil {
		return errors.Wrap(err, "Failed to open SQLite database")
	}
	defer db.Close()

	log.Debug("Creating users table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Creating affiliations table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL UNIQUE, prekey VARCHAR(1024))"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Creating certificates table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number blob NOT NULL, authority_key_identifier blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem blob NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}

	return nil
}

// NewUserRegistryPostgres opens a connecton to a postgres database
func NewUserRegistryPostgres(datasource string, clientTLSConfig *tls.ClientTLSConfig) (*sqlx.DB, error) {
	log.Debugf("Using postgres database, connecting to database...")

	dbName := getDBName(datasource)
	log.Debug("Database Name: ", dbName)

	if strings.Contains(dbName, "-") || strings.HasSuffix(dbName, ".db") {
		return nil, errors.Errorf("Database name '%s' cannot contain any '-' or end with '.db'", dbName)
	}

	if clientTLSConfig.Enabled {
		if len(clientTLSConfig.CertFiles) > 0 {
			root := clientTLSConfig.CertFiles[0]
			datasource = fmt.Sprintf("%s sslrootcert=%s", datasource, root)
		}

		cert := clientTLSConfig.Client.CertFile
		key := clientTLSConfig.Client.KeyFile
		datasource = fmt.Sprintf("%s sslcert=%s sslkey=%s", datasource, cert, key)
	}

	connStr := getConnStr(datasource)

	log.Debug("Connecting to PostgreSQL server, using connection string: ", MaskDBCred(connStr))
	db, err := sqlx.Open("postgres", connStr)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open Postgres database")
	}

	err = db.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to connect to Postgres database")
	}

	err = createPostgresDatabase(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Postgres database: %s")
	}

	log.Debugf("Connecting to database '%s', using connection string: '%s'", dbName, MaskDBCred(datasource))
	db, err = sqlx.Open("postgres", datasource)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to open database '%s' in Postgres server", dbName)
	}

	err = createPostgresTables(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Postgres tables")
	}

	return db, nil
}

func createPostgresDatabase(dbName string, db *sqlx.DB) error {
	log.Debugf("Creating Postgres Database (%s) if it does not exist...", dbName)

	query := "CREATE DATABASE " + dbName
	_, err := db.Exec(query)
	if err != nil {
		if !strings.Contains(err.Error(), fmt.Sprintf("database \"%s\" already exists", dbName)) {
			return errors.Wrap(err, "Failed to execute create database query")
		}
	}

	return nil
}

// createPostgresDB creates postgres database
func createPostgresTables(dbName string, db *sqlx.DB) error {
	log.Debug("Creating users table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Creating affiliations table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL UNIQUE, prekey VARCHAR(1024))"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Creating certificates table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	return nil
}

// NewUserRegistryMySQL opens a connection to a postgres database
func NewUserRegistryMySQL(datasource string, clientTLSConfig *tls.ClientTLSConfig, csp bccsp.BCCSP) (*sqlx.DB, error) {
	log.Debugf("Using MySQL database, connecting to database...")

	dbName := getDBName(datasource)
	log.Debug("Database Name: ", dbName)

	re := regexp.MustCompile(`\/([a-zA-z]+)`)
	connStr := re.ReplaceAllString(datasource, "/")

	if clientTLSConfig.Enabled {
		tlsConfig, err := tls.GetClientTLSConfig(clientTLSConfig, csp)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to get client TLS for MySQL")
		}

		mysql.RegisterTLSConfig("custom", tlsConfig)
	}

	log.Debug("Connecting to MySQL server, using connection string: ", MaskDBCred(connStr))
	db, err := sqlx.Open("mysql", connStr)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open MySQL database")
	}

	err = db.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to connect to MySQL database")
	}

	err = createMySQLDatabase(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create MySQL database")
	}

	log.Debugf("Connecting to database '%s', using connection string: '%s'", dbName, MaskDBCred(datasource))
	db, err = sqlx.Open("mysql", datasource)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to open database (%s) in MySQL server", dbName)
	}

	err = createMySQLTables(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create MySQL tables")
	}

	return db, nil
}

func createMySQLDatabase(dbName string, db *sqlx.DB) error {
	log.Debugf("Creating MySQL Database (%s) if it does not exist...", dbName)

	_, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + dbName)
	if err != nil {
		return errors.Wrap(err, "Failed to execute create database query")
	}

	return nil
}

func createMySQLTables(dbName string, db *sqlx.DB) error {
	log.Debug("Creating users table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) NOT NULL, token blob, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER, max_enrollments INTEGER, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}

	log.Debug("Creating affiliations table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL, prekey VARCHAR(1024))"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}

	log.Debug("Creating index on 'name' in the affiliations table")
	if _, err := db.Exec("CREATE INDEX name_index on affiliations (name)"); err != nil {
		if !strings.Contains(err.Error(), "Error 1061") { // Error 1061: Duplicate key name, index already exists
			return errors.Wrap(err, "Error creating index on affiliations table")
		}
	}

	log.Debug("Creating certificates table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number varbinary(128) NOT NULL, authority_key_identifier varbinary(128) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT 0, revoked_at timestamp DEFAULT 0, pem varbinary(4096) NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
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

// MaskDBCred hides DB credentials in connection string
func MaskDBCred(str string) string {
	matches := dbURLRegex.FindStringSubmatch(str)

	// If there is a match, there should be three entries: 1 for
	// the match and 9 for submatches (see dbURLRegex regular expression)
	if len(matches) == 10 {
		matchIdxs := dbURLRegex.FindStringSubmatchIndex(str)
		substr := str[matchIdxs[0]:matchIdxs[1]]
		for idx := 1; idx < len(matches); idx++ {
			if matches[idx] != "" {
				if strings.Index(matches[idx], "user=") == 0 {
					substr = strings.Replace(substr, matches[idx], "user=****", 1)
				} else if strings.Index(matches[idx], "password=") == 0 {
					substr = strings.Replace(substr, matches[idx], "password=****", 1)
				} else {
					substr = strings.Replace(substr, matches[idx], "****", 1)
				}
			}
		}
		str = str[:matchIdxs[0]] + substr + str[matchIdxs[1]:len(str)]
	}
	return str
}

// UpdateSchema updates the database tables to use the latest schema
func UpdateSchema(db *sqlx.DB) error {
	log.Debug("Checking database schema...")

	switch db.DriverName() {
	case "sqlite3": // SQLite does not support altering columns. However, data types in SQLite are not rigid and thus no action is really required
		return nil
	case "mysql":
		return updateMySQLSchema(db)
	case "postgres":
		return updatePostgresSchema(db)
	default:
		return errors.Errorf("Unsupported database type: %s", db.DriverName())
	}
}

func updateMySQLSchema(db *sqlx.DB) error {
	log.Debug("Update MySQL schema if using outdated schema")
	var err error

	_, err = db.Exec("ALTER TABLE users MODIFY id VARCHAR(255), MODIFY type VARCHAR(256), MODIFY affiliation VARCHAR(256)")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE users MODIFY attributes TEXT")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE affiliations DROP INDEX name;")
	if err != nil {
		if !strings.Contains(err.Error(), "Error 1091") { // Indicates that index not found
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE affiliations MODIFY name VARCHAR(1024), MODIFY prekey VARCHAR(1024)")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE affiliations ADD INDEX name_index (name)")
	if err != nil {
		if !strings.Contains(err.Error(), "Error 1061") { // Error 1061: Duplicate key name, index already exists
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE certificates MODIFY id VARCHAR(255)")
	if err != nil {
		return err
	}

	return nil
}

func updatePostgresSchema(db *sqlx.DB) error {
	log.Debug("Update Postgres schema if using outdated schema")
	var err error

	_, err = db.Exec("ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(255), ALTER COLUMN type TYPE VARCHAR(256), ALTER COLUMN affiliation TYPE VARCHAR(256)")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE users ALTER COLUMN attributes TYPE TEXT")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE affiliations ALTER COLUMN name TYPE VARCHAR(1024), ALTER COLUMN prekey TYPE VARCHAR(1024)")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE certificates ALTER COLUMN id TYPE VARCHAR(255)")
	if err != nil {
		return err
	}

	return nil
}
