/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db_test

import (
	"errors"
	"testing"

	"github.com/hyperledger/fabric-ca/lib/server/db"
	"github.com/hyperledger/fabric-ca/lib/server/db/mocks"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/gomega"
)

func TestTX(t *testing.T) {
	gt := NewGomegaWithT(t)

	mockDB := &mocks.SqlxDB{}
	fabDB := db.New(mockDB, "", nil)
	mockTX := &mocks.SqlxTx{}
	fabTx := &db.TX{
		TX:     mockTX,
		Record: fabDB,
	}
	gt.Expect(fabTx).NotTo(BeNil())

	// Select
	mockTX.SelectReturns(nil)
	err := fabTx.Select("", nil, "")
	gt.Expect(err).NotTo(HaveOccurred())

	mockTX.SelectReturns(errors.New("Select Error"))
	err = fabTx.Select("", nil, "")
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("Select Error"))

	// Exec
	mockResult := &mocks.Result{}
	mockResult.On("RowsAffected").Return(int64(2), nil)
	mockTX.ExecReturns(mockResult, nil)
	res, err := fabTx.Exec("", "")
	gt.Expect(err).NotTo(HaveOccurred())

	rows, err := res.RowsAffected()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(rows).To(Equal(int64(2)))

	mockTX.ExecReturns(nil, errors.New("Exec Error"))
	res, err = fabTx.Exec("", "")
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("Exec Error"))

	// Get
	mockTX.GetReturns(nil)
	err = fabTx.Get("", nil, "")
	gt.Expect(err).NotTo(HaveOccurred())

	mockTX.GetReturns(errors.New("Get Error"))
	err = fabTx.Get("", nil, "")
	gt.Expect(err.Error()).To(Equal("Get Error"))

	// Queryx
	mockTX.QueryxReturns(&sqlx.Rows{}, nil)
	r, err := fabTx.Queryx("", "")
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(r).NotTo(BeNil())

	mockTX.QueryxReturns(nil, errors.New("Queryx Error"))
	_, err = fabTx.Queryx("", "")
	gt.Expect(err.Error()).To(Equal("Queryx Error"))

	// Rebind
	mockTX.RebindReturns("Select * from")
	query := fabTx.Rebind("")
	gt.Expect(query).To(Equal("Select * from"))

	// Commit
	mockTX.CommitReturns(nil)
	err = fabTx.Commit("")
	gt.Expect(err).NotTo(HaveOccurred())

	mockTX.CommitReturns(errors.New("commit error"))
	err = fabTx.Commit("")
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("commit error"))

	// Rollback
	mockTX.RollbackReturns(nil)
	err = fabTx.Rollback("")
	gt.Expect(err).NotTo(HaveOccurred())

	mockTX.RollbackReturns(errors.New("rollback error"))
	err = fabTx.Rollback("")
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("rollback error"))
}
