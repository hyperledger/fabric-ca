/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db_test

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/lib/server/db/mocks"
	"github.com/hyperledger/fabric-ca/lib/server/db/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("migrator", func() {
	var (
		mockMigrator  *mocks.Migrator
		currentLevels *util.Levels
		srvLevels     *util.Levels
	)

	BeforeEach(func() {
		mockMigrator = &mocks.Migrator{}

		currentLevels = &util.Levels{
			Identity:    0,
			Affiliation: 0,
			Certificate: 0,
			Credential:  0,
			Nonce:       0,
			RAInfo:      0,
		}

		srvLevels = &util.Levels{
			Identity:    1,
			Affiliation: 1,
			Certificate: 1,
			Credential:  1,
			Nonce:       1,
			RAInfo:      1,
		}
	})

	Context("migrating users table", func() {
		BeforeEach(func() {
			mockMigrator.MigrateUsersTableReturns(errors.New("failed to migrate"))
		})
		It("rolls back transaction if migration fails", func() {
			db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(mockMigrator.RollbackCallCount()).To(Equal(1))
		})

		It("returns an error if rolling back transaction fails", func() {
			mockMigrator.RollbackReturns(errors.New("failed to rollback"))
			err := db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to rollback"))
		})
	})

	Context("migrating affiliations table", func() {
		BeforeEach(func() {
			mockMigrator.MigrateAffiliationsTableReturns(errors.New("failed to migrate"))
		})
		It("rolls back transaction if migration fails", func() {
			db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(mockMigrator.RollbackCallCount()).To(Equal(1))
		})

		It("returns an error if rolling back transaction fails", func() {
			mockMigrator.RollbackReturns(errors.New("failed to rollback"))
			err := db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to rollback"))
		})
	})

	Context("migrating certificates table", func() {
		BeforeEach(func() {
			mockMigrator.MigrateCertificatesTableReturns(errors.New("failed to migrate"))
		})
		It("rolls back transaction if migration fails", func() {
			db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(mockMigrator.RollbackCallCount()).To(Equal(1))
		})

		It("returns an error if rolling back transaction fails", func() {
			mockMigrator.RollbackReturns(errors.New("failed to rollback"))
			err := db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to rollback"))
		})
	})

	Context("migrating credentials table", func() {
		BeforeEach(func() {
			mockMigrator.MigrateCredentialsTableReturns(errors.New("failed to migrate"))
		})
		It("rolls back transaction if migration fails", func() {
			db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(mockMigrator.RollbackCallCount()).To(Equal(1))
		})

		It("returns an error if rolling back transaction fails", func() {
			mockMigrator.RollbackReturns(errors.New("failed to rollback"))
			err := db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to rollback"))
		})
	})

	Context("migrating nonce table", func() {
		BeforeEach(func() {
			mockMigrator.MigrateNoncesTableReturns(errors.New("failed to migrate"))
		})
		It("rolls back transaction if migration fails", func() {
			db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(mockMigrator.RollbackCallCount()).To(Equal(1))
		})

		It("returns an error if rolling back transaction fails", func() {
			mockMigrator.RollbackReturns(errors.New("failed to rollback"))
			err := db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to rollback"))
		})
	})

	Context("migrating rainfo table", func() {
		BeforeEach(func() {
			mockMigrator.MigrateRAInfoTableReturns(errors.New("failed to migrate"))
		})
		It("rolls back transaction if migration fails", func() {
			db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(mockMigrator.RollbackCallCount()).To(Equal(1))
		})

		It("returns an error if rolling back transaction fails", func() {
			mockMigrator.RollbackReturns(errors.New("failed to rollback"))
			err := db.Migrate(mockMigrator, currentLevels, srvLevels)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("failed to rollback"))
		})
	})

	It("migrates database to the level of the server", func() {
		err := db.Migrate(mockMigrator, currentLevels, srvLevels)
		fmt.Println("err: ", err)
		Expect(err).NotTo(HaveOccurred())
	})
})
