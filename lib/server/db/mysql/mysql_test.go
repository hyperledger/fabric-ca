/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mysql_test

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/hyperledger/fabric-ca/lib/server/db/mysql"
	"github.com/hyperledger/fabric-ca/lib/server/db/mysql/mocks"
	"github.com/hyperledger/fabric-ca/lib/tls"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	testdataDir = "../../../../../testdata"
)

var _ = Describe("Mysql", func() {
	var (
		db     *mysql.Mysql
		mockDB *mocks.FabricCADB
	)

	BeforeEach(func() {
		tls := &tls.ClientTLSConfig{
			Enabled:   true,
			CertFiles: []string{filepath.Join(testdataDir, "root.pem")},
		}
		db = mysql.NewDB(
			"root:rootpw@tcp(localhost:3306)/fabric_ca_db",
			"",
			tls,
			nil,
			nil,
		)
		mockDB = &mocks.FabricCADB{}
	})

	Context("open connection to database", func() {
		It("fails to open database connection of root cert files missing from tls config", func() {
			db.TLS.CertFiles = nil
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(
				ContainSubstring(
					"Failed to get client TLS for MySQL: No trusted root certificates for TLS were provided",
				),
			)
			Expect(db.SqlxDB).To(BeNil())
		})

		It("fails to open database connection if unable to ping database", func() {
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(db.SqlxDB).To(BeNil())
		})
	})

	Context("pinging database", func() {
		It("returns an error if unable to ping database", func() {
			mockDB.PingContextReturns(errors.New("ping error"))
			db.SqlxDB = mockDB

			err := db.PingContext(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to ping to MySQL database: ping error"))
		})

		It("returns no error if able to ping database", func() {
			db.SqlxDB = mockDB

			err := db.PingContext(context.Background())
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("creating fabric ca database", func() {
		It("returns an error if unable execute create fabric ca database sql", func() {
			mockDB.ExecReturns(nil, errors.New("error creating database"))
			db.SqlxDB = mockDB
			_, err := db.CreateDatabase()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL database: Failed to execute create database query: error creating database"))
		})

		It("creates the fabric ca database", func() {
			db.SqlxDB = mockDB

			_, err := db.CreateDatabase()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("creating tables", func() {
		It("returns an error if unable to create users table", func() {
			mockDB.ExecReturnsOnCall(0, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating users table: unable to create table"))
		})

		It("returns an error if unable to create affiliations table", func() {
			mockDB.ExecReturnsOnCall(1, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating affiliations table: unable to create table"))
		})

		It("returns an error if unable to create index on affiliations table", func() {
			mockDB.ExecReturnsOnCall(2, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating index on affiliations table: unable to create table"))
		})

		It("returns an error if unable to create certificates table", func() {
			mockDB.ExecReturnsOnCall(3, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating certificates table: unable to create table"))
		})

		It("returns an error if unable to create credentials table", func() {
			mockDB.ExecReturnsOnCall(4, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating credentials table: unable to create table"))
		})

		It("returns an error if unable to create revocation_authority_info table", func() {
			mockDB.ExecReturnsOnCall(5, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating revocation_authority_info table: unable to create table"))
		})

		It("returns an error if unable to create nonces table", func() {
			mockDB.ExecReturnsOnCall(6, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating nonces table: unable to create table"))
		})

		It("returns an error if unable to create properties table", func() {
			mockDB.ExecReturnsOnCall(7, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: Error creating properties table: unable to create table"))
		})

		It("returns an error if unable to insert default value in properties table", func() {
			mockDB.ExecReturnsOnCall(8, nil, errors.New("unable to insert default values"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create MySQL tables: unable to insert default values"))
		})

		It("creates the fabric ca tables", func() {
			db.SqlxDB = mockDB

			err := db.CreateTables()
			Expect(err).NotTo(HaveOccurred())
		})

	})
})
