/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util_test

import (
	"github.com/hyperledger/fabric-ca/lib/server/db/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("util", func() {

	Context("GetDBName", func() {
		It("parses the datasource for mysql and returns only the database name", func() {
			datasource := "root:rootpw@tcp(localhost:3306)/fabric_ca_db"

			dbName := util.GetDBName(datasource)
			Expect(dbName).To(Equal("fabric_ca_db"))
		})

		It("parses the datasource for postgres and returns only the database name", func() {
			datasource := "host=localhost port=5432 user=root password=rootpw dbname=fabric_ca"

			dbName := util.GetDBName(datasource)
			Expect(dbName).To(Equal("fabric_ca"))
		})
	})

	Context("MaskDBCred", func() {
		It("masks the credentails in the datasource string for mysql", func() {
			datasource := "root:rootpw@tcp(localhost:3306)/fabric_ca_db"

			masked := util.MaskDBCred(datasource)
			Expect(masked).To(Equal("****:****@tcp(localhost:3306)/fabric_ca_db"))
		})

		It("masks the credentails in the datasource string for postgres", func() {
			datasource := "host=localhost port=5432 user=root password=rootpw dbname=fabric_ca"

			masked := util.MaskDBCred(datasource)
			Expect(masked).To(Equal("host=localhost port=5432 user=**** password=**** dbname=fabric_ca"))
		})
	})

	Context("GetCADatasource", func() {
		It("returns a datasource with a unique database name", func() {
			datasourceStr := util.GetCADataSource("sqlite3", "fabric.db", 2)
			Expect(datasourceStr).To(Equal("fabric_ca2.db"))

			datasourceStr = util.GetCADataSource("mysql", "root:rootpw@tcp(localhost:3306)/fabric_db", 2)
			Expect(datasourceStr).To(Equal("root:rootpw@tcp(localhost:3306)/fabric_db_ca2"))

			datasourceStr = util.GetCADataSource("postgres", "host=localhost port=5432 user=root password=rootpw dbname=fabric", 2)
			Expect(datasourceStr).To(Equal("host=localhost port=5432 user=root password=rootpw dbname=fabric_ca2"))
		})
	})
})
