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
	"path/filepath"
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

// Levels contains the levels of identities, affiliations, and certificates
type Levels struct {
	Identity    int
	Affiliation int
	Certificate int
}

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
	log.Debugf("Creating SQLite database (%s) if it does not exist...", datasource)
	db, err := sqlx.Open("sqlite3", datasource)
	if err != nil {
		return errors.Wrap(err, "Failed to open SQLite database")
	}
	defer db.Close()

	err = doTransaction(db, createAllSQLiteTables)
	if err != nil {
		return err
	}

	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err = db.Exec(db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0')"))
	if err != nil {
		if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errors.Wrap(err, "Failed to initialize properties table")
		}
	}
	return nil
}

func createAllSQLiteTables(tx *sqlx.Tx, args ...interface{}) error {
	err := createSQLiteIdentityTable(tx)
	if err != nil {
		return err
	}
	err = createSQLiteAffiliationTable(tx)
	if err != nil {
		return err
	}
	err = createSQLiteCertificateTable(tx)
	if err != nil {
		return err
	}
	return nil
}

func createSQLiteIdentityTable(tx *sqlx.Tx) error {
	log.Debug("Creating users table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	return nil
}

func createSQLiteAffiliationTable(tx *sqlx.Tx) error {
	log.Debug("Creating affiliations table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL UNIQUE, prekey VARCHAR(1024), level INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	return nil
}

func createSQLiteCertificateTable(tx *sqlx.Tx) error {
	log.Debug("Creating certificates table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number blob NOT NULL, authority_key_identifier blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem blob NOT NULL, level INTEGER DEFAULT 0, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	return nil
}

// NewUserRegistryPostgres opens a connection to a postgres database
func NewUserRegistryPostgres(datasource string, clientTLSConfig *tls.ClientTLSConfig) (*sqlx.DB, error) {
	log.Debugf("Using postgres database, connecting to database...")

	dbName := getDBName(datasource)
	log.Debugf("Database Name: %s", dbName)

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

	dbNames := []string{dbName, "postgres", "template1"}
	var db *sqlx.DB
	var pingErr, err error

	for _, dbName := range dbNames {
		connStr := getConnStr(datasource, dbName)
		log.Debugf("Connecting to PostgreSQL server, using connection string: %s", MaskDBCred(connStr))

		db, err = sqlx.Open("postgres", connStr)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to open Postgres database")
		}

		pingErr = db.Ping()
		if pingErr == nil {
			break
		}
		log.Warningf("Failed to connect to database '%s'", dbName)
	}

	if pingErr != nil {
		return nil, errors.Errorf("Failed to connect to Postgres database. Postgres requires connecting to a specific database, the following databases were tried: %s. Please create one of these database before continuing", dbNames)
	}

	err = createPostgresDatabase(dbName, db)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create Postgres database")
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
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Creating affiliations table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL UNIQUE, prekey VARCHAR(1024), level INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Creating certificates table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, level INTEGER DEFAULT 0, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err := db.Exec(db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0')"))
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate key") {
			return err
		}
	}
	return nil
}

// NewUserRegistryMySQL opens a connection to a postgres database
func NewUserRegistryMySQL(datasource string, clientTLSConfig *tls.ClientTLSConfig, csp bccsp.BCCSP) (*sqlx.DB, error) {
	log.Debugf("Using MySQL database, connecting to database...")

	dbName := getDBName(datasource)
	log.Debugf("Database Name: %s", dbName)

	re := regexp.MustCompile(`\/([0-9,a-z,A-Z$_]+)`)
	connStr := re.ReplaceAllString(datasource, "/")

	if clientTLSConfig.Enabled {
		tlsConfig, err := tls.GetClientTLSConfig(clientTLSConfig, csp)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to get client TLS for MySQL")
		}

		mysql.RegisterTLSConfig("custom", tlsConfig)
	}

	log.Debugf("Connecting to MySQL server, using connection string: %s", MaskDBCred(connStr))
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
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) NOT NULL, token blob, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER, max_enrollments INTEGER, level INTEGER DEFAULT 0, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Creating affiliations table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(1024) NOT NULL, prekey VARCHAR(1024), level INTEGER DEFAULT 0, PRIMARY KEY (id))"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Creating index on 'name' in the affiliations table")
	if _, err := db.Exec("CREATE INDEX name_index on affiliations (name)"); err != nil {
		if !strings.Contains(err.Error(), "Error 1061") { // Error 1061: Duplicate key name, index already exists
			return errors.Wrap(err, "Error creating index on affiliations table")
		}
	}
	log.Debug("Creating certificates table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number varbinary(128) NOT NULL, authority_key_identifier varbinary(128) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT 0, revoked_at timestamp DEFAULT 0, pem varbinary(4096) NOT NULL, level INTEGER DEFAULT 0, PRIMARY KEY(serial_number, authority_key_identifier)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err := db.Exec(db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0')"))
	if err != nil {
		if !strings.Contains(err.Error(), "1062") { // MySQL error code for duplicate entry
			return err
		}
	}
	return nil
}

// getDBName gets database name from connection string
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

// GetCADataSource returns a datasource with a unqiue database name
func GetCADataSource(dbtype, datasource string, cacount int) string {
	if dbtype == "sqlite3" {
		ext := filepath.Ext(datasource)
		dbName := strings.TrimSuffix(filepath.Base(datasource), ext)
		datasource = fmt.Sprintf("%s_ca%d%s", dbName, cacount, ext)
	} else {
		dbName := getDBName(datasource)
		datasource = strings.Replace(datasource, dbName, fmt.Sprintf("%s_ca%d", dbName, cacount), 1)
	}
	return datasource
}

// GetConnStr gets connection string without database
func getConnStr(datasource string, dbname string) string {
	re := regexp.MustCompile(`(dbname=)([^\s]+)`)
	connStr := re.ReplaceAllString(datasource, fmt.Sprintf("dbname=%s", dbname))
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
func UpdateSchema(db *sqlx.DB, levels *Levels) error {
	log.Debug("Checking database schema...")

	switch db.DriverName() {
	case "sqlite3":
		return updateSQLiteSchema(db, levels)
	case "mysql":
		return updateMySQLSchema(db)
	case "postgres":
		return updatePostgresSchema(db)
	default:
		return errors.Errorf("Unsupported database type: %s", db.DriverName())
	}
}

// UpdateDBLevel updates the levels for the tables in the database
func UpdateDBLevel(db *sqlx.DB, levels *Levels) error {
	log.Debugf("Updating database level to %+v", levels)

	_, err := db.Exec(db.Rebind("UPDATE properties SET value = ? WHERE (property = 'identity.level')"), levels.Identity)
	if err != nil {
		return err
	}
	_, err = db.Exec(db.Rebind("UPDATE properties SET value = ? WHERE (property = 'affiliation.level')"), levels.Affiliation)
	if err != nil {
		return err
	}
	_, err = db.Exec(db.Rebind("UPDATE properties SET value = ? WHERE (property = 'certificate.level')"), levels.Certificate)
	if err != nil {
		return err
	}

	return nil
}

func currentDBLevels(db *sqlx.DB) (*Levels, error) {
	var err error
	var identityLevel, affiliationLevel, certificateLevel int

	err = db.Get(&identityLevel, "Select value FROM properties WHERE (property = 'identity.level')")
	if err != nil {
		return nil, err
	}
	err = db.Get(&affiliationLevel, "Select value FROM properties WHERE (property = 'affiliation.level')")
	if err != nil {
		return nil, err
	}
	err = db.Get(&certificateLevel, "Select value FROM properties WHERE (property = 'certificate.level')")
	if err != nil {
		return nil, err
	}

	return &Levels{
		Identity:    identityLevel,
		Affiliation: affiliationLevel,
		Certificate: certificateLevel,
	}, nil
}

func updateSQLiteSchema(db *sqlx.DB, serverLevels *Levels) error {
	log.Debug("Update SQLite schema, if using outdated schema")

	var err error

	currentLevels, err := currentDBLevels(db)
	if err != nil {
		return err
	}

	if currentLevels.Identity < serverLevels.Identity {
		log.Debug("Upgrade identities table")
		err := doTransaction(db, updateIdentitiesTable, currentLevels.Identity)
		if err != nil {
			return err
		}
	}

	if currentLevels.Affiliation < serverLevels.Affiliation {
		log.Debug("Upgrade affiliation table")
		err := doTransaction(db, updateAffiliationsTable, currentLevels.Affiliation)
		if err != nil {
			return err
		}
	}

	if currentLevels.Certificate < serverLevels.Certificate {
		log.Debug("Upgrade certificates table")
		err := doTransaction(db, updateCertificatesTable, currentLevels.Certificate)
		if err != nil {
			return err
		}
	}

	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current users table to users_old and then creating a new user table using
// the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func updateIdentitiesTable(tx *sqlx.Tx, args ...interface{}) error {
	identityLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if identityLevel < 1 {
		_, err := tx.Exec("ALTER TABLE users RENAME TO users_old")
		if err != nil {
			return err
		}
		err = createSQLiteIdentityTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec("INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments) SELECT id, token, type, affiliation, attributes, state, max_enrollments FROM users_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE users_old")
		if err != nil {
			return err
		}
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current affiliations table to affiliations_old and then creating a new user
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func updateAffiliationsTable(tx *sqlx.Tx, args ...interface{}) error {
	affiliationLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if affiliationLevel < 1 {
		_, err := tx.Exec("ALTER TABLE affiliations RENAME TO affiliations_old")
		if err != nil {
			return err
		}
		err = createSQLiteAffiliationTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec("INSERT INTO affiliations (name, prekey) SELECT name, prekey FROM affiliations_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE affiliations_old")
		if err != nil {
			return err
		}
	}
	return nil
}

// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current certificates table to certificates_old and then creating a new certificates
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func updateCertificatesTable(tx *sqlx.Tx, args ...interface{}) error {
	certificateLevel := args[0].(int)
	// Future schema updates should add to the logic below to handle other levels
	if certificateLevel < 1 {
		_, err := tx.Exec("ALTER TABLE certificates RENAME TO certificates_old")
		if err != nil {
			return err
		}
		err = createSQLiteCertificateTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec("INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem) SELECT id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem FROM certificates_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec("DROP TABLE certificates_old")
		if err != nil {
			return err
		}
	}
	return nil
}

func updateMySQLSchema(db *sqlx.DB) error {
	log.Debug("Update MySQL schema if using outdated schema")
	var err error

	_, err = db.Exec("ALTER TABLE users MODIFY id VARCHAR(255), MODIFY type VARCHAR(256), MODIFY affiliation VARCHAR(1024)")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE users MODIFY attributes TEXT")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE users ADD COLUMN level INTEGER DEFAULT 0 AFTER max_enrollments")
	if err != nil {
		if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE certificates ADD COLUMN level INTEGER DEFAULT 0 AFTER pem")
	if err != nil {
		if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE affiliations ADD COLUMN level INTEGER DEFAULT 0 AFTER prekey")
	if err != nil {
		if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE affiliations DROP INDEX name;")
	if err != nil {
		if !strings.Contains(err.Error(), "Error 1091") { // Indicates that index not found
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE affiliations ADD COLUMN id INT NOT NULL PRIMARY KEY AUTO_INCREMENT FIRST")
	if err != nil {
		if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
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

	_, err = db.Exec("ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(255), ALTER COLUMN type TYPE VARCHAR(256), ALTER COLUMN affiliation TYPE VARCHAR(1024)")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE users ALTER COLUMN attributes TYPE TEXT")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE users ADD COLUMN level INTEGER DEFAULT 0")
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE certificates ADD COLUMN level INTEGER DEFAULT 0")
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	_, err = db.Exec("ALTER TABLE affiliations ADD COLUMN level INTEGER DEFAULT 0")
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
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

func doTransaction(db *sqlx.DB, doit func(tx *sqlx.Tx, args ...interface{}) error, args ...interface{}) error {
	tx := db.MustBegin()
	err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			log.Errorf("Error encounted while rolling back transaction: %s", err2)
			return err
		}
		return err
	}

	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "Error encountered while committing transaction")
	}
	return nil
}
