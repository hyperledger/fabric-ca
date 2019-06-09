/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"context"
	"regexp"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/go-sql-driver/mysql"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

var (
	re = regexp.MustCompile(`\/([0-9,a-z,A-Z$_]+)`)
)

// Mysql defines MySQL database
type Mysql struct {
	SqlxDB  db.FabricCADB
	TLS     *tls.ClientTLSConfig
	CSP     bccsp.BCCSP
	CAName  string
	Metrics *db.Metrics

	datasource string
	dbName     string
}

// NewDB create a MySQL database
func NewDB(
	datasource,
	caName string,
	clientTLSConfig *tls.ClientTLSConfig,
	csp bccsp.BCCSP,
	metrics *db.Metrics,
) *Mysql {
	log.Debugf("Using MySQL database, connecting to database...")
	return &Mysql{
		TLS:        clientTLSConfig,
		CSP:        csp,
		datasource: datasource,
		CAName:     caName,
		Metrics:    metrics,
	}
}

// Connect connects to a MySQL server
func (m *Mysql) Connect() error {
	datasource := m.datasource
	clientTLSConfig := m.TLS

	m.dbName = util.GetDBName(datasource)
	log.Debugf("Database Name: %s", m.dbName)

	connStr := re.ReplaceAllString(datasource, "/")

	if clientTLSConfig.Enabled {
		tlsConfig, err := tls.GetClientTLSConfig(clientTLSConfig, m.CSP)
		if err != nil {
			return errors.WithMessage(err, "Failed to get client TLS for MySQL")
		}

		mysql.RegisterTLSConfig("custom", tlsConfig)
	}

	log.Debugf("Connecting to MySQL server, using connection string: %s", util.MaskDBCred(connStr))
	sqlxdb, err := sqlx.Connect("mysql", connStr)
	if err != nil {
		return errors.Wrap(err, "Failed to connect to MySQL database")
	}

	m.SqlxDB = db.New(sqlxdb, m.CAName, m.Metrics)
	return nil
}

// PingContext pings the database
func (m *Mysql) PingContext(ctx context.Context) error {
	err := m.SqlxDB.PingContext(ctx)
	if err != nil {
		return errors.Wrap(err, "Failed to ping to MySQL database")
	}
	return nil
}

// Create creates database and tables
func (m *Mysql) Create() (*db.DB, error) {
	db, err := m.CreateDatabase()
	if err != nil {
		return nil, err
	}
	err = m.CreateTables()
	if err != nil {
		return nil, err
	}
	return db, nil
}

// CreateDatabase creates database
func (m *Mysql) CreateDatabase() (*db.DB, error) {
	datasource := m.datasource
	dbName := m.dbName
	err := m.createDatabase()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create MySQL database")
	}

	log.Debugf("Connecting to database '%s', using connection string: '%s'", dbName, util.MaskDBCred(datasource))
	sqlxdb, err := sqlx.Open("mysql", datasource)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to open database (%s) in MySQL server", dbName)
	}

	m.SqlxDB = db.New(sqlxdb, m.CAName, m.Metrics)

	return m.SqlxDB.(*db.DB), nil
}

// CreateTables creates table
func (m *Mysql) CreateTables() error {
	err := m.createTables()
	if err != nil {
		return errors.Wrap(err, "Failed to create MySQL tables")
	}
	return nil
}

func (m *Mysql) createDatabase() error {
	dbName := m.dbName
	log.Debugf("Creating MySQL Database (%s) if it does not exist...", dbName)

	_, err := m.SqlxDB.Exec("CreateDatabase", "CREATE DATABASE IF NOT EXISTS "+dbName)
	if err != nil {
		return errors.Wrap(err, "Failed to execute create database query")
	}

	return nil
}

func (m *Mysql) createTables() error {
	db := m.SqlxDB
	log.Debug("Creating users table if it doesn't exist")
	if _, err := db.Exec("CreateUsersTable", "CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) NOT NULL, token blob, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER, max_enrollments INTEGER, level INTEGER DEFAULT 0, incorrect_password_attempts INTEGER DEFAULT 0, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	log.Debug("Creating affiliations table if it doesn't exist")
	if _, err := db.Exec("CreateAffiliationsTable", "CREATE TABLE IF NOT EXISTS affiliations (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(1024) NOT NULL, prekey VARCHAR(1024), level INTEGER DEFAULT 0, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	log.Debug("Creating index on 'name' in the affiliations table")
	if _, err := db.Exec("CreateAffiliationsIndex", "CREATE INDEX name_index on affiliations (name)"); err != nil {
		if !strings.Contains(err.Error(), "Error 1061") { // Error 1061: Duplicate key name, index already exists
			return errors.Wrap(err, "Error creating index on affiliations table")
		}
	}
	log.Debug("Creating certificates table if it doesn't exist")
	if _, err := db.Exec("CreateCertificatesTable", "CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number varbinary(128) NOT NULL, authority_key_identifier varbinary(128) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT 0, revoked_at timestamp DEFAULT 0, pem varbinary(4096) NOT NULL, level INTEGER DEFAULT 0, PRIMARY KEY(serial_number, authority_key_identifier)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	log.Debug("Creating credentials table if it doesn't exist")
	if _, err := db.Exec("CreateCredentialsTable", "CREATE TABLE IF NOT EXISTS credentials (id VARCHAR(255), revocation_handle varbinary(128) NOT NULL, cred varbinary(4096) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT 0, revoked_at timestamp DEFAULT 0, level INTEGER DEFAULT 0, PRIMARY KEY(revocation_handle)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating credentials table")
	}
	log.Debug("Creating revocation_authority_info table if it does not exist")
	if _, err := db.Exec("CreateRevocationAuthorityTable", "CREATE TABLE IF NOT EXISTS revocation_authority_info (epoch INTEGER, next_handle INTEGER, lasthandle_in_pool INTEGER, level INTEGER DEFAULT 0, PRIMARY KEY (epoch)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating revocation_authority_info table")
	}
	log.Debug("Creating nonces table if it does not exist")
	if _, err := db.Exec("CreateNoncesTable", "CREATE TABLE IF NOT EXISTS nonces (val VARCHAR(255) NOT NULL, expiry timestamp, level INTEGER DEFAULT 0, PRIMARY KEY (val)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating nonces table")
	}
	log.Debug("Creating properties table if it does not exist")
	if _, err := db.Exec("CreatePropertiesTable", "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"); err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err := db.Exec("CreatePropertiesTable", db.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0'), ('credential.level', '0'), ('rcinfo.level', '0'), ('nonce.level', '0')"))
	if err != nil {
		if !strings.Contains(err.Error(), "1062") { // MySQL error code for duplicate entry
			return err
		}
	}
	return nil
}
