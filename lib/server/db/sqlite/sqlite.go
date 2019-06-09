/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

//go:generate counterfeiter -o mocks/create.go -fake-name Create . Create

// Create is interface that defines functions need to create database transaction
type Create interface {
	Exec(funcName, query string, args ...interface{}) (sql.Result, error)
	Rebind(query string) string
	Rollback(funcName string) error
	Commit(funcName string) error
}

// Sqlite defines SQLite database
type Sqlite struct {
	SqlxDB   db.FabricCADB
	CreateTx Create
	CAName   string
	Metrics  *db.Metrics

	datasource string
}

// NewDB creates a SQLite database
func NewDB(datasource, caName string, metrics *db.Metrics) *Sqlite {
	log.Debugf("Using sqlite database, connect to database in home (%s) directory", datasource)
	return &Sqlite{
		datasource: datasource,
		CAName:     caName,
		Metrics:    metrics,
	}
}

// Connect connects to a SQLite database
func (s *Sqlite) Connect() error {
	var err error
	log.Debugf("Creating SQLite database (%s) if it does not exist...", s.datasource)
	sqlxDB, err := sqlx.Connect("sqlite3", s.datasource+"?_busy_timeout=5000")
	if err != nil {
		return errors.Wrap(err, "Failed to open sqlite3 DB")
	}
	s.SqlxDB = db.New(sqlxDB, s.CAName, s.Metrics)
	return nil
}

// PingContext pings the database
func (s *Sqlite) PingContext(ctx context.Context) error {
	err := s.SqlxDB.PingContext(ctx)
	if err != nil {
		return errors.Wrap(err, "Failed to ping to SQLite database")
	}
	return nil
}

// Create creates database and tables
func (s *Sqlite) Create() (*db.DB, error) {
	s.CreateTx = s.SqlxDB.BeginTx()
	err := s.CreateTables()
	if err != nil {
		return nil, err
	}
	return s.SqlxDB.(*db.DB), nil
}

// CreateTables creates table
func (s *Sqlite) CreateTables() error {
	err := s.doTransaction("CreateTable", createAllSQLiteTables)
	if err != nil {
		return err
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
	log.Debug("Successfully opened sqlite3 DB")
	s.SqlxDB.SetMaxOpenConns(1)

	return nil
}

func createAllSQLiteTables(tx Create, args ...interface{}) error {
	err := createIdentityTable(tx)
	if err != nil {
		return err
	}
	err = createAffiliationTable(tx)
	if err != nil {
		return err
	}
	err = createCertificateTable(tx)
	if err != nil {
		return err
	}
	err = createCredentialsTable(tx)
	if err != nil {
		return err
	}
	err = createRevocationComponentTable(tx)
	if err != nil {
		return err
	}
	err = createNoncesTable(tx)
	if err != nil {
		return err
	}
	err = createPropertiesTable(tx)
	if err != nil {
		return err
	}
	return nil
}

func createIdentityTable(tx Create) error {
	log.Debug("Creating users table if it does not exist")
	if _, err := tx.Exec("CreateUsersTable", "CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0, incorrect_password_attempts INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating users table")
	}
	return nil
}

func createAffiliationTable(tx Create) error {
	log.Debug("Creating affiliations table if it does not exist")
	if _, err := tx.Exec("CreateAffiliationsTable", "CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(1024) NOT NULL UNIQUE, prekey VARCHAR(1024), level INTEGER DEFAULT 0)"); err != nil {
		return errors.Wrap(err, "Error creating affiliations table")
	}
	return nil
}

func createCertificateTable(tx Create) error {
	log.Debug("Creating certificates table if it does not exist")
	if _, err := tx.Exec("CreateCertificatesTable", "CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(255), serial_number blob NOT NULL, authority_key_identifier blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem blob NOT NULL, level INTEGER DEFAULT 0, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return errors.Wrap(err, "Error creating certificates table")
	}
	return nil
}

func createCredentialsTable(tx Create) error {
	log.Debug("Creating credentials table if it does not exist")
	if _, err := tx.Exec("CreateCredentialsTable", "CREATE TABLE IF NOT EXISTS credentials (id VARCHAR(255), revocation_handle blob NOT NULL, cred blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, level INTEGER DEFAULT 0, PRIMARY KEY(revocation_handle))"); err != nil {
		return errors.Wrap(err, "Error creating credentials table")
	}
	return nil
}

func createRevocationComponentTable(tx Create) error {
	log.Debug("Creating revocation_authority_info table if it does not exist")
	if _, err := tx.Exec("CreateRevocationAuthorityTable", "CREATE TABLE IF NOT EXISTS revocation_authority_info (epoch INTEGER, next_handle INTEGER, lasthandle_in_pool INTEGER, level INTEGER DEFAULT 0, PRIMARY KEY(epoch))"); err != nil {
		return errors.Wrap(err, "Error creating revocation_authority_info table")
	}
	return nil
}

func createNoncesTable(tx Create) error {
	log.Debug("Creating nonces table if it does not exist")
	if _, err := tx.Exec("CreateNoncesTable", "CREATE TABLE IF NOT EXISTS nonces (val VARCHAR(1024) NOT NULL UNIQUE, expiry timestamp, level INTEGER DEFAULT 0, PRIMARY KEY(val))"); err != nil {
		return errors.Wrap(err, "Error creating nonces table")
	}
	return nil
}

func createPropertiesTable(tx Create) error {
	log.Debug("Creating properties table if it does not exist")
	_, err := tx.Exec("CreatePropertiesTable", "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))")
	if err != nil {
		return errors.Wrap(err, "Error creating properties table")
	}
	_, err = tx.Exec("CreatePropertiesTable", tx.Rebind("INSERT INTO properties (property, value) VALUES ('identity.level', '0'), ('affiliation.level', '0'), ('certificate.level', '0'), ('credential.level', '0'), ('rcinfo.level', '0'), ('nonce.level', '0')"))
	if err != nil {
		if !strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errors.Wrap(err, "Failed to initialize properties table")
		}
	}
	return nil
}

func (s *Sqlite) doTransaction(funcName string, doit func(tx Create, args ...interface{}) error, args ...interface{}) error {
	tx := s.CreateTx
	err := doit(tx, args...)
	if err != nil {
		err2 := tx.Rollback(funcName)
		if err2 != nil {
			log.Errorf("Error encountered while rolling back transaction: %s", err2)
			return err
		}
		return err
	}

	err = tx.Commit(funcName)
	if err != nil {
		return errors.Wrap(err, "Error encountered while committing transaction")
	}
	return nil
}
