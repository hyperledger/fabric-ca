/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres

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
	// Future schema updates should add to the logic below to handle other levels
	curLevel := m.CurLevels.Identity
	res := []struct {
		columnName string `db:"column_name"`
	}{}
	const funcName = "MigrateUsersTable"
	if curLevel < 1 {
		log.Debug("Upgrade identity table to level 1")
		_, err := tx.Exec(funcName, "ALTER TABLE users ALTER COLUMN id TYPE VARCHAR(255), ALTER COLUMN type TYPE VARCHAR(256), ALTER COLUMN affiliation TYPE VARCHAR(1024)")
		if err != nil {
			return err
		}
		_, err = tx.Exec(funcName, "ALTER TABLE users ALTER COLUMN attributes TYPE TEXT")
		if err != nil {
			return err
		}
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='users' and column_name='level'"
		err = tx.Select(funcName, &res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err = tx.Exec(funcName, "ALTER TABLE users ADD COLUMN level INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
			}
		}
		curLevel++
	}
	if curLevel < 2 {
		log.Debug("Upgrade identity table to level 2")
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='users' and column_name='incorrect_password_attempts'"
		err := tx.Select(funcName, &res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err = tx.Exec(funcName, "ALTER TABLE users ADD COLUMN incorrect_password_attempts INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
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
		res := []struct {
			columnName string `db:"column_name"`
		}{}
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='certificates' and column_name='level'"
		err := tx.Select(funcName, &res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err := tx.Exec(funcName, "ALTER TABLE certificates ADD COLUMN level INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
			}
		}
		_, err = tx.Exec(funcName, "ALTER TABLE certificates ALTER COLUMN id TYPE VARCHAR(255)")
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
		res := []struct {
			columnName string `db:"column_name"`
		}{}
		query := "SELECT column_name  FROM information_schema.columns WHERE table_name='affiliations' and column_name='level'"
		err := tx.Select(funcName, &res, tx.Rebind(query))
		if err != nil {
			return err
		}
		if len(res) == 0 {
			_, err := tx.Exec(funcName, "ALTER TABLE affiliations ADD COLUMN level INTEGER DEFAULT 0")
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					return err
				}
			}
		}
		_, err = tx.Exec(funcName, "ALTER TABLE affiliations ALTER COLUMN name TYPE VARCHAR(1024), ALTER COLUMN prekey TYPE VARCHAR(1024)")
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
