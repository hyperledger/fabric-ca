/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite_test

import (
	"context"
	"errors"
	"os"

	"github.com/hyperledger/fabric-ca/lib/server/db/sqlite"
	"github.com/hyperledger/fabric-ca/lib/server/db/sqlite/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	testdataDir = "../../../../../testdata"
	dbName      = "fabric_ca.db"
)

var _ = Describe("Sqlite", func() {
	var (
		err          error
		db           *sqlite.Sqlite
		mockDB       *mocks.FabricCADB
		mockCreateTx *mocks.Create
	)

	BeforeEach(func() {
		db = sqlite.NewDB(dbName, "", nil)
		mockDB = &mocks.FabricCADB{}
		mockCreateTx = &mocks.Create{}
	})

	AfterEach(func() {
		os.Remove(dbName)
	})

	It("connect to database", func() {
		err := db.Connect()
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns no error when creating databse", func() {
		err := db.Connect()
		Expect(err).NotTo(HaveOccurred())
		_, err = db.Create()
		Expect(err).NotTo(HaveOccurred())
	})

	Context("pinging database", func() {
		It("returns an error if unable to ping database", func() {
			mockDB.PingContextReturns(errors.New("ping error"))
			db.SqlxDB = mockDB

			err := db.PingContext(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to ping to SQLite database: ping error"))
		})

		It("returns no error if able to ping database", func() {
			db.SqlxDB = mockDB

			err := db.PingContext(context.Background())
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("creating tables", func() {
		It("return an error if unable to create users table", func() {
			mockCreateTx.ExecReturnsOnCall(0, nil, errors.New("creating error"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Error creating users table: creating error"))
		})

		It("return an error if unable to create affiliations table", func() {
			mockCreateTx.ExecReturnsOnCall(1, nil, errors.New("creating error"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Error creating affiliations table: creating error"))
		})

		It("return an error if unable to create certificates table", func() {
			mockCreateTx.ExecReturnsOnCall(2, nil, errors.New("creating error"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Error creating certificates table: creating error"))
		})

		It("return an error if unable to create credentials table", func() {
			mockCreateTx.ExecReturnsOnCall(3, nil, errors.New("creating error"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Error creating credentials table: creating error"))
		})

		It("return an error if unable to create revocation_authority_info table", func() {
			mockCreateTx.ExecReturnsOnCall(4, nil, errors.New("creating error"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Error creating revocation_authority_info table: creating error"))
		})

		It("return an error if unable to create nonces table", func() {
			mockCreateTx.ExecReturnsOnCall(5, nil, errors.New("creating error"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Error creating nonces table: creating error"))
		})

		It("return an error if unable to create properties table", func() {
			mockCreateTx.ExecReturnsOnCall(6, nil, errors.New("creating error"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Error creating properties table: creating error"))
		})

		It("return an error if unable to load properties table with data", func() {
			mockCreateTx.ExecReturnsOnCall(7, nil, errors.New("failed to load data"))
			db.CreateTx = mockCreateTx
			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Failed to initialize properties table: failed to load data"))
		})

		It("creates the fabric ca tables", func() {
			db.CreateTx = mockCreateTx

			db.SqlxDB = mockDB
			err = db.CreateTables()
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
