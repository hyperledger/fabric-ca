/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite_test

import (
	"errors"

	"github.com/hyperledger/fabric-ca/lib/server/db/sqlite"
	"github.com/hyperledger/fabric-ca/lib/server/db/sqlite/mocks"
	"github.com/hyperledger/fabric-ca/lib/server/db/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Migrator", func() {
	var (
		migrator *sqlite.Migrator
		mockTx   *mocks.FabricCATx
	)

	BeforeEach(func() {
		mockTx = &mocks.FabricCATx{}
		curLevels := &util.Levels{
			Identity:    0,
			Affiliation: 0,
			Certificate: 0,
			Credential:  0,
			RAInfo:      0,
			Nonce:       0,
		}
		serverLevels := &util.Levels{
			Identity:    2,
			Affiliation: 2,
			Certificate: 2,
			Credential:  2,
			RAInfo:      2,
			Nonce:       2,
		}
		migrator = sqlite.NewMigrator(mockTx, curLevels, serverLevels)
	})

	Context("users table", func() {
		It("returns error if modifying columns id, type, and affilaition fails", func() {
			mockTx.ExecReturnsOnCall(0, nil, errors.New("failed to modify id, type, and affilaition columns"))
			migrator.Tx = mockTx

			err := migrator.MigrateUsersTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to modify id, type, and affilaition columns"))
		})

		It("returns error if modifying attributes column fails", func() {
			mockTx.ExecReturnsOnCall(1, nil, errors.New("failed to modify attributes column"))
			migrator.Tx = mockTx

			err := migrator.MigrateUsersTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Error creating users table: failed to modify attributes column"))
		})

		It("returns error if adding level column fails", func() {
			mockTx.QueryxReturns(nil, nil)
			mockTx.ExecReturnsOnCall(2, nil, errors.New("failed to add level columns"))
			migrator.Tx = mockTx

			err := migrator.MigrateUsersTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to add level columns"))
		})

		It("returns error if adding incorrect_password_attempts column fails", func() {
			mockTx.QueryxReturns(nil, nil)
			mockTx.ExecReturnsOnCall(3, nil, errors.New("failed to add incorrect_password_attempts columns"))
			migrator.Tx = mockTx

			err := migrator.MigrateUsersTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to add incorrect_password_attempts columns"))
		})

		It("returns error if updating properties to new users table level fails", func() {
			mockTx.QueryxReturns(nil, nil)
			mockTx.ExecReturnsOnCall(4, nil, errors.New("failed to update properties table"))
			migrator.Tx = mockTx

			err := migrator.MigrateUsersTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to update properties table"))
		})

		It("returns error if migrating a user in the users table fails", func() {
			mockTx.QueryxReturns(nil, errors.New("failed to query users"))
			migrator.Tx = mockTx

			err := migrator.MigrateUsersTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to get identities that need to be updated: failed to query users"))
		})

		It("migrates successfully", func() {
			mockTx.QueryxReturns(nil, nil)
			migrator.Tx = mockTx

			err := migrator.MigrateUsersTable()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("certificates table", func() {
		It("returns error if adding level column fails", func() {
			mockTx.ExecReturnsOnCall(0, nil, errors.New("failed to add level columns"))
			migrator.Tx = mockTx

			err := migrator.MigrateCertificatesTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to add level columns"))
		})

		It("returns error if modifying id column fails", func() {
			mockTx.ExecReturnsOnCall(1, nil, errors.New("failed to modify id column"))
			migrator.Tx = mockTx

			err := migrator.MigrateCertificatesTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Error creating certificates table: failed to modify id column"))
		})

		It("returns error if updating properties to new certificate table level fails", func() {
			mockTx.ExecReturnsOnCall(2, nil, errors.New("failed to update properties table"))
			migrator.Tx = mockTx

			err := migrator.MigrateCertificatesTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to update properties table"))
		})

		It("migrates successfully", func() {
			err := migrator.MigrateCertificatesTable()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("affiliations table", func() {
		It("returns error if adding level column fails", func() {
			mockTx.ExecReturnsOnCall(0, nil, errors.New("failed to add level columns"))
			migrator.Tx = mockTx

			err := migrator.MigrateAffiliationsTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to add level columns"))
		})

		It("returns error if modifying name and prekey column fails", func() {
			mockTx.ExecReturnsOnCall(1, nil, errors.New("failed to modify columns"))
			migrator.Tx = mockTx

			err := migrator.MigrateAffiliationsTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Error creating affiliations table: failed to modify columns"))
		})

		It("returns error if updating properties to new affiliations table level fails", func() {
			mockTx.ExecReturnsOnCall(2, nil, errors.New("failed to update properties table"))
			migrator.Tx = mockTx

			err := migrator.MigrateAffiliationsTable()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to update properties table"))
		})

		It("migrates successfully", func() {
			err := migrator.MigrateAffiliationsTable()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("migrates credentials table", func() {
		err := migrator.MigrateCredentialsTable()
		Expect(err).NotTo(HaveOccurred())
	})

	It("migrates rainfo table", func() {
		err := migrator.MigrateRAInfoTable()
		Expect(err).NotTo(HaveOccurred())
	})

	It("migrates nonces table", func() {
		err := migrator.MigrateNoncesTable()
		Expect(err).NotTo(HaveOccurred())
	})

	Context("rollback", func() {
		It("returns an error if it fails", func() {
			mockTx.RollbackReturns(errors.New("failed to rollback"))
			migrator.Tx = mockTx

			err := migrator.Rollback()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to rollback"))
		})

		It("completes with no error on success", func() {
			err := migrator.Rollback()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("commit", func() {
		It("returns an error if it fails", func() {
			mockTx.CommitReturns(errors.New("failed to commit"))
			migrator.Tx = mockTx

			err := migrator.Commit()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Error encountered while committing database migration changes: failed to commit"))
		})

		It("completes with no error on success", func() {
			err := migrator.Commit()
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
