/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package postgres_test

import (
	"context"
	"path/filepath"

	"github.com/hyperledger/fabric-ca/lib/server/db/postgres"
	"github.com/hyperledger/fabric-ca/lib/server/db/postgres/mocks"
	"github.com/hyperledger/fabric-ca/lib/tls"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
)

const (
	testdataDir = "../../../../../testdata"
)

var _ = Describe("Postgres", func() {
	var (
		db     *postgres.Postgres
		mockDB *mocks.FabricCADB
	)

	BeforeEach(func() {
		tls := &tls.ClientTLSConfig{
			Enabled:   true,
			CertFiles: []string{filepath.Join(testdataDir, "root.pem")},
		}
		db = postgres.NewDB(
			"host=localhost port=5432 user=root password=rootpw dbname=fabric_ca",
			"",
			tls,
			nil,
		)
		mockDB = &mocks.FabricCADB{}
	})

	Context("open connection to database", func() {
		It("fails to connect if the contains incorrect syntax", func() {
			db = postgres.NewDB(
				"hos) (t=localhost port=5432 user=root password=rootpw dbname=fabric-ca",
				"",
				nil,
				nil,
			)
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("Database name 'fabric-ca' cannot contain any '-' or end with '.db'"))

			db = postgres.NewDB(
				"host=localhost port=5432 user=root password=rootpw dbname=fabric_ca.db",
				"",
				nil,
				nil,
			)
			err = db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("Database name 'fabric_ca.db' cannot contain any '-' or end with '.db'"))
		})

		It("fails to open database connection of root cert files missing from tls config", func() {
			db.TLS.CertFiles = nil
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("No trusted root certificates for TLS were provided"))
			Expect(db.SqlxDB).To(BeNil())
		})

		It("has datasource with TLS connection parameters when TLS is enabled", func() {
			db.TLS = &tls.ClientTLSConfig{
				Enabled:   true,
				CertFiles: []string{"root.pem"},
				Client: tls.KeyCertFiles{
					KeyFile:  "key.pem",
					CertFile: "cert.pem",
				},
			}
			db.Connect()
			Expect(db.Datasource()).To(
				ContainSubstring("sslrootcert=root.pem sslcert=cert.pem sslkey=key.pem"),
			)
		})

		It("does not have has datasource with TLS connection parameters when TLS is enabled", func() {
			db.TLS = &tls.ClientTLSConfig{
				Enabled: false,
			}
			db.Connect()
			Expect(db.Datasource()).ToNot(ContainSubstring("sslrootcert"))
		})

		It("fail to open database connection if unable to ping database", func() {
			err := db.Connect()
			Expect(err).To(HaveOccurred())
			Expect(
				err.Error()).Should(
				ContainSubstring(
					"Failed to connect to Postgres database. Postgres requires connecting to a specific database, the following databases were tried: [fabric_ca postgres template1]",
				),
			)
		})
	})

	Context("pinging database", func() {
		It("returns an error if unable to ping database", func() {
			mockDB.PingContextReturns(errors.New("ping error"))
			db.SqlxDB = mockDB

			err := db.PingContext(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Failed to ping to Postgres database: ping error"))
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
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres database: Failed to execute create database query: error creating database"))
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
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating users table: unable to create table"))
		})

		It("returns an error if unable to create users index", func() {
			mockDB.ExecReturnsOnCall(1, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating users id index: unable to create table"))
		})

		It("returns an error if unable to create affiliations table", func() {
			mockDB.ExecReturnsOnCall(2, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating affiliations table: unable to create table"))
		})

		It("returns an error if unable to create certificates table", func() {
			mockDB.ExecReturnsOnCall(3, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating certificates table: unable to create table"))
		})

		It("returns an error if unable to create credentails table", func() {
			mockDB.ExecReturnsOnCall(4, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating credentials table: unable to create table"))
		})

		It("returns an error if unable to create revocation_authority_info table", func() {
			mockDB.ExecReturnsOnCall(5, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating revocation_authority_info table: unable to create table"))
		})

		It("returns an error if unable to create nonces table", func() {
			mockDB.ExecReturnsOnCall(6, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating nonces table: unable to create table"))
		})

		It("returns an error if unable to create properties table", func() {
			mockDB.ExecReturnsOnCall(7, nil, errors.New("unable to create table"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: Error creating properties table: unable to create table"))
		})

		It("returns an error if unable to insert default value in properties table", func() {
			mockDB.ExecReturnsOnCall(8, nil, errors.New("unable to insert default values"))

			db.SqlxDB = mockDB
			err := db.CreateTables()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("Failed to create Postgres tables: unable to insert default values"))
		})

		It("creates the fabric ca tables", func() {
			db.SqlxDB = mockDB

			err := db.CreateTables()
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
