/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"strings"

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
		_, err := tx.Exec(funcName, "ALTER TABLE users MODIFY id VARCHAR(255), MODIFY type VARCHAR(256), MODIFY affiliation VARCHAR(1024)")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "ALTER TABLE users MODIFY attributes TEXT")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "ALTER TABLE users ADD COLUMN level INTEGER DEFAULT 0 AFTER max_enrollments")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
		curLevel++
	}
	if curLevel < 2 {
		log.Debug("Upgrade identity table to level 2")
		_, err := tx.Exec(funcName, "ALTER TABLE users ADD COLUMN incorrect_password_attempts INTEGER DEFAULT 0 AFTER level")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
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
func (m *Migrator) MigrateCertificatesTable() error {
	tx := m.Tx
	const funcName = "MigrateCertificatesTable"
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Certificate < 1 {
		log.Debug("Upgrade certificates table to level 1")
		_, err := tx.Exec(funcName, "ALTER TABLE certificates ADD COLUMN level INTEGER DEFAULT 0 AFTER pem")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
		_, err = tx.Exec(funcName, "ALTER TABLE certificates MODIFY id VARCHAR(255)")
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
func (m *Migrator) MigrateAffiliationsTable() error {
	tx := m.Tx
	const funcName = "MigrateAffiliationsTable"
	// Future schema updates should add to the logic below to handle other levels
	if m.CurLevels.Affiliation < 1 {
		log.Debug("Upgrade affiliations table to level 1")
		_, err := tx.Exec(funcName, "ALTER TABLE affiliations ADD COLUMN level INTEGER DEFAULT 0 AFTER prekey")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
		_, err = tx.Exec(funcName, "ALTER TABLE affiliations DROP INDEX name;")
		if err != nil {
			if !strings.Contains(err.Error(), "Error 1091") { // Indicates that index not found
				return err
			}
		}
		_, err = tx.Exec(funcName, "ALTER TABLE affiliations ADD COLUMN id INT NOT NULL PRIMARY KEY AUTO_INCREMENT FIRST")
		if err != nil {
			if !strings.Contains(err.Error(), "1060") { // Already using the latest schema
				return err
			}
		}
		_, err = tx.Exec(funcName, "ALTER TABLE affiliations MODIFY name VARCHAR(1024), MODIFY prekey VARCHAR(1024)")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "ALTER TABLE affiliations ADD INDEX name_index (name)")
		if err != nil {
			if !strings.Contains(err.Error(), "Error 1061") { // Error 1061: Duplicate key name, index already exists
				return err
			}
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
