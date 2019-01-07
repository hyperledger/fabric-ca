/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/db/util"
)

//go:generate counterfeiter -o mocks/migrator.go -fake-name Migrator . Migrator

// Migrator is the interface that defines a migrator
type Migrator interface {
	MigrateUsersTable() error
	MigrateCertificatesTable() error
	MigrateAffiliationsTable() error
	MigrateCredentialsTable() error
	MigrateRAInfoTable() error
	MigrateNoncesTable() error
	Rollback() error
	Commit() error
}

// Migrate updates the database tables to use the latest schema and does
// data migration if needed
func Migrate(migrator Migrator, currentLevels, srvLevels *util.Levels) error {
	if currentLevels.Identity < srvLevels.Identity {
		log.Debug("Migrating users table...")
		err := migrator.MigrateUsersTable()
		if err != nil {
			log.Errorf("Error encountered while migrating users table, rolling back changes: %s", err)
			return migrator.Rollback()
		}
	}

	if currentLevels.Affiliation < srvLevels.Affiliation {
		log.Debug("Migrating affiliation table...")
		err := migrator.MigrateAffiliationsTable()
		if err != nil {
			log.Errorf("Error encountered while migrating affiliations table, rolling back changes: %s", err)
			return migrator.Rollback()
		}
	}

	if currentLevels.Certificate < srvLevels.Certificate {
		log.Debug("Upgrade certificates table...")
		err := migrator.MigrateCertificatesTable()
		if err != nil {
			log.Errorf("Error encountered while migrating certificates table, rolling back changes: %s", err)
			return migrator.Rollback()
		}
	}

	if currentLevels.Credential < srvLevels.Credential {
		log.Debug("Migrating credentials table...")
		err := migrator.MigrateCredentialsTable()
		if err != nil {
			log.Errorf("Error encountered while migrating credentials table, rolling back changes: %s", err)
			return migrator.Rollback()
		}
	}

	if currentLevels.Nonce < srvLevels.Nonce {
		log.Debug("Migrating nonces table...")
		err := migrator.MigrateNoncesTable()
		if err != nil {
			log.Errorf("Error encountered while migrating nonces table, rolling back changes: %s", err)
			return migrator.Rollback()
		}
	}

	if currentLevels.RAInfo < srvLevels.RAInfo {
		log.Debug("Migrating revocation_authority_info table...")
		err := migrator.MigrateRAInfoTable()
		if err != nil {
			log.Errorf("Error encountered while migrating revocation_authority_info table, rolling back changes: %s", err)
			return migrator.Rollback()
		}
	}

	return migrator.Commit()
}
