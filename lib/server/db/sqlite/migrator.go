/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/pkg/errors"
)

// Migrator defines migrator
type Migrator struct {
	Tx        db.FabricCATx
	CurLevels *util.Levels
	SrvLevels *util.Levels
}

// NewMigrator returns a migrator instance
func NewMigrator(tx db.FabricCATx, curLevels, srvLevels *util.Levels) *Migrator {
	return &Migrator{
		Tx:        tx,
		CurLevels: curLevels,
		SrvLevels: srvLevels,
	}
}

// MigrateUsersTable is responsible for migrating users table
func (m *Migrator) MigrateUsersTable() error {
	tx := m.Tx
	const funcName = "MigrateUsersTable"
	// Future schema updates should add to the logic below to handle other levels
	curLevel := m.CurLevels.Identity
	if curLevel < 1 {
		log.Debug("Upgrade identity table to level 1")
		_, err := tx.Exec(funcName, "ALTER TABLE users RENAME TO users_old")
		if err != nil {
			return err
		}
		err = createIdentityTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec(funcName, "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments) SELECT id, token, type, affiliation, attributes, state, max_enrollments FROM users_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "DROP TABLE users_old")
		if err != nil {
			return err
		}
		curLevel++
	}
	if curLevel < 2 {
		log.Debug("Upgrade identity table to level 2")
		_, err := tx.Exec(funcName, "ALTER TABLE users RENAME TO users_old")
		if err != nil {
			return err
		}
		err = createIdentityTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec(funcName, "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments, level) SELECT id, token, type, affiliation, attributes, state, max_enrollments, level FROM users_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "DROP TABLE users_old")
		if err != nil {
			return err
		}
		curLevel++
	}

	users, err := user.GetUserLessThanLevel(tx, m.SrvLevels.Identity)
	if err != nil {
		return err
	}

	for _, u := range users {
		err := u.Migrate(tx)
		if err != nil {
			return err
		}
	}

	_, err = tx.Exec(funcName, tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'identity.level')"), m.SrvLevels.Identity)
	if err != nil {
		return err
	}
	return nil
}

// MigrateCertificatesTable is responsible for migrating certificates table
// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current certificates table to certificates_old and then creating a new certificates
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m *Migrator) MigrateCertificatesTable() error {
	tx := m.Tx
	const funcName = "MigrateCertificatesTable"
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Certificate < 1 {
		log.Debug("Upgrade certificates table to level 1")
		_, err := tx.Exec(funcName, "ALTER TABLE certificates RENAME TO certificates_old")
		if err != nil {
			return err
		}
		err = createCertificateTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec(funcName, "INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem) SELECT id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem FROM certificates_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "DROP TABLE certificates_old")
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(funcName, tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'certificate.level')"), m.SrvLevels.Certificate)
	if err != nil {
		return err
	}
	return nil
}

// MigrateAffiliationsTable is responsible for migrating affiliations table
// SQLite has limited support for altering table columns, to upgrade the schema we
// require renaming the current affiliations table to affiliations_old and then creating a new user
// table using the new schema definition. Next, we proceed to copy the data from the old table to
// new table, and then drop the old table.
func (m *Migrator) MigrateAffiliationsTable() error {
	tx := m.Tx
	const funcName = "MigrateAffiliationsTable"
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Affiliation < 1 {
		log.Debug("Upgrade affiliations table to level 1")
		_, err := tx.Exec(funcName, "ALTER TABLE affiliations RENAME TO affiliations_old")
		if err != nil {
			return err
		}
		err = createAffiliationTable(tx)
		if err != nil {
			return err
		}
		// If coming from a table that did not yet have the level column then we can only copy columns that exist in both the tables
		_, err = tx.Exec(funcName, "INSERT INTO affiliations (name, prekey) SELECT name, prekey FROM affiliations_old")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "DROP TABLE affiliations_old")
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(funcName, tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'affiliation.level')"), m.SrvLevels.Affiliation)
	if err != nil {
		return err
	}
	return nil
}

// MigrateCredentialsTable is responsible for migrating credentials table
func (m *Migrator) MigrateCredentialsTable() error {
	_, err := m.Tx.Exec("MigrateCredentialsTable", m.Tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'credential.level')"), m.SrvLevels.Credential)
	return err
}

// MigrateRAInfoTable is responsible for migrating rainfo table
func (m *Migrator) MigrateRAInfoTable() error {
	_, err := m.Tx.Exec("MigrateRAInfoTable", m.Tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'rcinfo.level')"), m.SrvLevels.RAInfo)
	return err
}

// MigrateNoncesTable is responsible for migrating nonces table
func (m *Migrator) MigrateNoncesTable() error {
	_, err := m.Tx.Exec("MigrateNoncesTable", m.Tx.Rebind("UPDATE properties SET value = ? WHERE (property = 'nonce.level')"), m.SrvLevels.Nonce)
	return err
}

// Rollback is responsible for rollback transaction if an error is encountered
func (m *Migrator) Rollback() error {
	err := m.Tx.Rollback("Migration")
	if err != nil {
		log.Errorf("Error encountered while rolling back database migration changes: %s", err)
		return err
	}
	return nil
}

// Commit is responsible for committing the migration db transcation
func (m *Migrator) Commit() error {
	err := m.Tx.Commit("Migration")
	if err != nil {
		return errors.Wrap(err, "Error encountered while committing database migration changes")
	}
	return nil
}
