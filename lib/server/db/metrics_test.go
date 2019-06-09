/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db_test

import (
	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/lib/server/db/mocks"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("metrics", func() {
	var (
		fakeAPICounter   *metricsfakes.Counter
		fakeAPIHistogram *metricsfakes.Histogram
		testDB           *db.DB
	)

	BeforeEach(func() {
		fakeAPICounter = &metricsfakes.Counter{}
		fakeAPICounter.WithReturns(fakeAPICounter)

		fakeAPIHistogram = &metricsfakes.Histogram{}
		fakeAPIHistogram.WithReturns(fakeAPIHistogram)

		testDB = &db.DB{
			DB: &mocks.SqlxDB{},
			Metrics: &db.Metrics{
				APICounter:  fakeAPICounter,
				APIDuration: fakeAPIHistogram,
			},
			CAName: "testCA",
		}
	})

	Context("DB", func() {
		It("records metrics", func() {
			By("recoring count and duration metrics for calls to Select database API", func() {
				testDB.Select("selectFunc", nil, "")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(1))
				Expect(fakeAPICounter.WithArgsForCall(0)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(0)).To(Equal([]string{"ca_name", "testCA", "func_name", "selectFunc", "dbapi_name", "Select"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(1))
				Expect(fakeAPIHistogram.WithArgsForCall(0)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(0)).To(Equal([]string{"ca_name", "testCA", "func_name", "selectFunc", "dbapi_name", "Select"}))
			})

			By("counting number of calls to the Exec database API", func() {
				testDB.Exec("execFunc", "")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(2))
				Expect(fakeAPICounter.WithArgsForCall(1)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(1)).To(Equal([]string{"ca_name", "testCA", "func_name", "execFunc", "dbapi_name", "Exec"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(2))
				Expect(fakeAPIHistogram.WithArgsForCall(1)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(1)).To(Equal([]string{"ca_name", "testCA", "func_name", "execFunc", "dbapi_name", "Exec"}))
			})

			By("counting number of calls to the NamedExec database API", func() {
				testDB.NamedExec("namedExecFunc", "", nil)
				Expect(fakeAPICounter.AddCallCount()).To(Equal(3))
				Expect(fakeAPICounter.WithArgsForCall(2)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(2)).To(Equal([]string{"ca_name", "testCA", "func_name", "namedExecFunc", "dbapi_name", "NamedExec"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(3))
				Expect(fakeAPIHistogram.WithArgsForCall(2)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(2)).To(Equal([]string{"ca_name", "testCA", "func_name", "namedExecFunc", "dbapi_name", "NamedExec"}))
			})

			By("counting number of calls to the Get database API", func() {
				testDB.Get("getFunc", nil, "")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(4))
				Expect(fakeAPICounter.WithArgsForCall(3)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(3)).To(Equal([]string{"ca_name", "testCA", "func_name", "getFunc", "dbapi_name", "Get"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(4))
				Expect(fakeAPIHistogram.WithArgsForCall(3)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(3)).To(Equal([]string{"ca_name", "testCA", "func_name", "getFunc", "dbapi_name", "Get"}))
			})

			By("counting number of calls to the Queryx database API", func() {
				testDB.Queryx("queryxFunc", "", nil)
				Expect(fakeAPICounter.AddCallCount()).To(Equal(5))
				Expect(fakeAPICounter.WithArgsForCall(4)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(4)).To(Equal([]string{"ca_name", "testCA", "func_name", "queryxFunc", "dbapi_name", "Queryx"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(5))
				Expect(fakeAPIHistogram.WithArgsForCall(4)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(4)).To(Equal([]string{"ca_name", "testCA", "func_name", "queryxFunc", "dbapi_name", "Queryx"}))
			})
		})
	})

	Context("TX", func() {
		var fabTx *db.TX

		BeforeEach(func() {
			fabTx = &db.TX{
				TX:     &mocks.SqlxTx{},
				Record: testDB,
			}
		})

		It("records metrics", func() {
			By("recording count and duration metrics for calls to Select database API", func() {
				fabTx.Select("selectFunc", nil, "")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(1))
				Expect(fakeAPICounter.WithArgsForCall(0)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(0)).To(Equal([]string{"ca_name", "testCA", "func_name", "selectFunc", "dbapi_name", "Select"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(1))
				Expect(fakeAPIHistogram.WithArgsForCall(0)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(0)).To(Equal([]string{"ca_name", "testCA", "func_name", "selectFunc", "dbapi_name", "Select"}))
			})

			By("recording count and duration metrics for calls to Exec database API", func() {
				fabTx.Exec("execFunc", "")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(2))
				Expect(fakeAPICounter.WithArgsForCall(1)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(1)).To(Equal([]string{"ca_name", "testCA", "func_name", "execFunc", "dbapi_name", "Exec"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(2))
				Expect(fakeAPIHistogram.WithArgsForCall(1)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(1)).To(Equal([]string{"ca_name", "testCA", "func_name", "execFunc", "dbapi_name", "Exec"}))
			})

			By("recording count and duration metrics for calls to Get database API", func() {
				fabTx.Get("getFunc", nil, "")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(3))
				Expect(fakeAPICounter.WithArgsForCall(2)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(2)).To(Equal([]string{"ca_name", "testCA", "func_name", "getFunc", "dbapi_name", "Get"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(3))
				Expect(fakeAPIHistogram.WithArgsForCall(2)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(2)).To(Equal([]string{"ca_name", "testCA", "func_name", "getFunc", "dbapi_name", "Get"}))
			})

			By("recording count and duration metrics for calls to Queryx database API", func() {
				fabTx.Queryx("queryxFunc", "", nil)
				Expect(fakeAPICounter.AddCallCount()).To(Equal(4))
				Expect(fakeAPICounter.WithArgsForCall(3)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(3)).To(Equal([]string{"ca_name", "testCA", "func_name", "queryxFunc", "dbapi_name", "Queryx"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(4))
				Expect(fakeAPIHistogram.WithArgsForCall(3)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(3)).To(Equal([]string{"ca_name", "testCA", "func_name", "queryxFunc", "dbapi_name", "Queryx"}))
			})

			By("recording count and duration metrics for calls to Commit database API", func() {
				fabTx.Commit("commitFunc")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(5))
				Expect(fakeAPICounter.WithArgsForCall(4)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(4)).To(Equal([]string{"ca_name", "testCA", "func_name", "commitFunc", "dbapi_name", "Commit"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(5))
				Expect(fakeAPIHistogram.WithArgsForCall(4)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(4)).To(Equal([]string{"ca_name", "testCA", "func_name", "commitFunc", "dbapi_name", "Commit"}))
			})

			By("recording count and duration metrics for calls to Rollback database API", func() {
				fabTx.Rollback("rollbackFunc")
				Expect(fakeAPICounter.AddCallCount()).To(Equal(6))
				Expect(fakeAPICounter.WithArgsForCall(5)).NotTo(BeZero())
				Expect(fakeAPICounter.WithArgsForCall(5)).To(Equal([]string{"ca_name", "testCA", "func_name", "rollbackFunc", "dbapi_name", "Rollback"}))

				Expect(fakeAPIHistogram.ObserveCallCount()).To(Equal(6))
				Expect(fakeAPIHistogram.WithArgsForCall(5)).NotTo(BeZero())
				Expect(fakeAPIHistogram.WithArgsForCall(5)).To(Equal([]string{"ca_name", "testCA", "func_name", "rollbackFunc", "dbapi_name", "Rollback"}))
			})
		})
	})
})
