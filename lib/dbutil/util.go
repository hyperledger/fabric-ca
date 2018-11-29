/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dbutil

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/go-sql-driver/mysql"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

var (
	dbURLRegex = regexp.MustCompile("(Datasource:\\s*)?(\\S+):(\\S+)@|(Datasource:.*\\s)?(user=\\S+).*\\s(password=\\S+)|(Datasource:.*\\s)?(password=\\S+).*\\s(user=\\S+)")
)

// FabricCADB is the interface with functions implemented by sqlx.DB
// object that are used by Fabric CA server
type FabricCADB interface {
	IsInitialized() bool
	Select(dest interface{}, query string, args ...interface{}) error
	Exec(query string, args ...interface{}) (sql.Result, error)
	NamedExec(query string, arg interface{}) (sql.Result, error)
	Rebind(query string) string
	MustBegin() *sqlx.Tx
	// BeginTx has same behavior as MustBegin except it returns FabricCATx
	// instead of *sqlx.Tx
	BeginTx() FabricCATx
}

// FabricCATx is the interface with functions implemented by sqlx.Tx
// object that are used by Fabric CA server
type FabricCATx interface {
	Queryx(query string, args ...interface{}) (*sqlx.Rows, error)
	Select(dest interface{}, query string, args ...interface{}) error
	Rebind(query string) string
	Exec(query string, args ...interface{}) (sql.Result, error)
	Commit() error
	Rollback() error
}

// DB is an adapter for sqlx.DB and implements FabricCADB interface
type DB struct {
	*sqlx.DB
	// Indicates if database was successfully initialized
	IsDBInitialized bool
}

// Levels contains the levels of identities, affiliations, and certificates
type Levels struct {
	Identity    int
	Affiliation int
	Certificate int
	Credential  int
	RAInfo      int
	Nonce       int
}

// BeginTx implements BeginTx method of FabricCADB interface
func (db *DB) BeginTx() FabricCATx {
	return db.MustBegin()
}

// IsInitialized returns true if db is intialized, else false
func (db *DB) IsInitialized() bool {
	return db.IsDBInitialized
}

// NewUserRegistrySQLLite3 returns a pointer to a sqlite database
func NewUserRegistrySQLLite3(datasource string) (*DB, error) {
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

	return &DB{db, false}, nil
}

func createSQLiteDBTables(datasource string) error {
	log.Debugf("Creating SQLite database (%s) if it does not exist...", datasource)
	sqldb, err := sqlx.Open("sqlite3", datasource)
	if err != nil {
		return errors.Wrap(err, "Failed to open SQLite database")
	}
	db := &DB{sqldb, false}
	defer db.Close()

	err = doTransaction(db, createAllSQLiteTables)
	if err != nil {
		return err
	}

	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err = db.Exec(db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0'), ('credential.level', '0'), ('rcinfo.level', '0'), ('nonce.level', '0')"))
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
	err = createSQLiteCredentialsTable(tx)
	if err != nil {
		return err
	}
	err = createSQLiteRevocationComponentTable(tx)
	if err != nil {
		return err
	}
	err = createSQLiteNoncesTable(tx)
	if err != nil {
		return err
	}
	return nil
}

func createSQLiteIdentityTable(tx FabricCATx) error {
	log.Debug("Creating users table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0, incorrect_password_attempts INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	return nil
}

func createSQLiteAffiliationTable(tx FabricCATx) error {
	log.Debug("Creating affiliations table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL UNIQUE, prekey VARCHAR(1024), level INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	return nil
}

func createSQLiteCertificateTable(tx FabricCATx) error {
	log.Debug("Creating certificates table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number blob NOT NULL, authority_key_identifier blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem blob NOT NULL, level INTEGER DEFAULT 0, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	return nil
}

func createSQLiteCredentialsTable(tx FabricCATx) error {
	log.Debug("Creating credentials table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS credentials (id VARCHAR(255), revocation_handle blob NOT NULL, cred blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, level INTEGER DEFAULT 0, PRIMARY KEY(revocation_handle))"); err != nil {
		return errors.Wrap(err, "Error creating credentials table")
	}
	return nil
}

func createSQLiteRevocationComponentTable(tx FabricCATx) error {
	log.Debug("Creating revocation_authority_info table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS revocation_authority_info (epoch INTEGER, next_handle INTEGER, lasthandle_in_pool INTEGER, level INTEGER DEFAULT 0, PRIMARY KEY(epoch))"); err != nil {
		return errors.Wrap(err, "Error creating revocation_authority_info table")
	}
	return nil
}

func createSQLiteNoncesTable(tx FabricCATx) error {
	log.Debug("Creating nonces table if it does not exist")
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS nonces (val VARCHAR(1024) NOT NULL UNIQUE, expiry timestamp, level INTEGER DEFAULT 0, PRIMARY KEY(val))"); err != nil {
		return errors.Wrap(err, "Error creating nonces table")
	}
	return nil
}

// NewUserRegistryPostgres opens a connection to a postgres database
func NewUserRegistryPostgres(datasource string, clientTLSConfig *tls.ClientTLSConfig) (*DB, error) {
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

	return &DB{db, false}, nil
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
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0, incorrect_password_attempts INTEGER DEFAULT 0)"); err != nil {
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
	log.Debug("Creating credentials table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS credentials (id VARCHAR(255), revocation_handle bytea NOT NULL, cred bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, level INTEGER DEFAULT 0, PRIMARY KEY(revocation_handle))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Creating revocation_authority_info table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS revocation_authority_info (epoch INTEGER, next_handle INTEGER, lasthandle_in_pool INTEGER, level INTEGER DEFAULT 0, PRIMARY KEY(epoch))"); err != nil {
		return errors.Wrap(err, "Error creating revocation_authority_info table")
	}
	log.Debug("Creating nonces table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS nonces (val VARCHAR(255) NOT NULL UNIQUE, expiry timestamp, level INTEGER DEFAULT 0, PRIMARY KEY (val))"); err != nil {
		return errors.Wrap(err, "Error creating nonces table")
	}
	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err := db.Exec(db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0'), ('credential.level', '0'), ('rcinfo.level', '0'), ('nonce.level', '0')"))
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate key") {
			return err
		}
	}
	return nil
}

// NewUserRegistryMySQL opens a connection to a postgres database
func NewUserRegistryMySQL(datasource string, clientTLSConfig *tls.ClientTLSConfig, csp bccsp.BCCSP) (*DB, error) {
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

	return &DB{db, false}, nil
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
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) NOT NULL, token blob, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER, max_enrollments INTEGER, level INTEGER DEFAULT 0, incorrect_password_attempts INTEGER DEFAULT 0, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Creating affiliations table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS affiliations (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(1024) NOT NULL, prekey VARCHAR(1024), level INTEGER DEFAULT 0, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
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
	log.Debug("Creating credentials table if it doesn't exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS credentials (id VARCHAR(255), revocation_handle varbinary(128) NOT NULL, cred varbinary(4096) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT 0, revoked_at timestamp DEFAULT 0, level INTEGER DEFAULT 0, PRIMARY KEY(revocation_handle)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Creating revocation_authority_info table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS revocation_authority_info (epoch INTEGER, next_handle INTEGER, lasthandle_in_pool INTEGER, level INTEGER DEFAULT 0, PRIMARY KEY (epoch)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating revocation_authority_info table")
	}
	log.Debug("Creating nonces table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS nonces (val VARCHAR(255) NOT NULL, expiry timestamp, level INTEGER DEFAULT 0, PRIMARY KEY (val)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating nonces table")
	}
	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err := db.Exec(db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0'), ('credential.level', '0'), ('rcinfo.level', '0'), ('nonce.level', '0')"))
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

// CurrentDBLevels returns current levels from the database
func CurrentDBLevels(db *DB) (*Levels, error) {
	var err error
	var identityLevel, affiliationLevel, certificateLevel, credentialLevel, rcinfoLevel, nonceLevel int

	err = getProperty(db, "identity.level", &identityLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "affiliation.level", &affiliationLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "certificate.level", &certificateLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "credential.level", &credentialLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "rcinfo.level", &rcinfoLevel)
	if err != nil {
		return nil, err
	}
	err = getProperty(db, "nonce.level", &nonceLevel)
	if err != nil {
		return nil, err
	}
	return &Levels{
		Identity:    identityLevel,
		Affiliation: affiliationLevel,
		Certificate: certificateLevel,
		Credential:  credentialLevel,
		RAInfo:      rcinfoLevel,
		Nonce:       nonceLevel,
	}, nil
}

func getProperty(db *DB, propName string, val *int) error {
	err := db.Get(val, db.Rebind("Select value FROM properties WHERE (property = ?)"), propName)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return nil
	}
	return err
}

func doTransaction(db *DB, doit func(tx *sqlx.Tx, args ...interface{}) error, args ...interface{}) error {
	tx := db.MustBegin()
	err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			log.Errorf("Error encountered while rolling back transaction: %s", err2)
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
