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
	"github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/jmoiron/sqlx"
	. "github.com/onsi/gomega"
)

func TestDB(t *testing.T) {
	gt := NewGomegaWithT(t)

	mockDB := &mocks.SqlxDB{}
	fabDB := db.New(mockDB, "", nil)
	gt.Expect(fabDB).NotTo(BeNil())

	mockDB.MustBeginReturns(&sqlx.Tx{})
	tx := fabDB.BeginTx()
	gt.Expect(tx).NotTo(BeNil())

	fabDB.IsDBInitialized = true
	b := fabDB.IsInitialized()
	gt.Expect(b).To(Equal(true))

	fabDB.SetDBInitialized(false)
	gt.Expect(fabDB.IsDBInitialized).To(Equal(false))

	// Select
	mockDB.SelectReturns(nil)
	err := fabDB.Select("", nil, "")
	gt.Expect(err).NotTo(HaveOccurred())

	mockDB.SelectReturns(errors.New("Select Error"))
	err = fabDB.Select("", nil, "")
	gt.Expect(err.Error()).To(Equal("Select Error"))

	// Exec
	mockResult := &mocks.Result{}
	mockResult.On("RowsAffected").Return(int64(2), nil)
	mockDB.ExecReturns(mockResult, nil)
	res, err := fabDB.DB.Exec("", "")
	gt.Expect(err).NotTo(HaveOccurred())

	rows, err := res.RowsAffected()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(rows).To(Equal(int64(2)))

	mockDB.ExecReturns(nil, errors.New("Exec Error"))
	res, err = fabDB.Exec("", "")
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("Exec Error"))

	// NamedExec
	mockResult = &mocks.Result{}
	mockResult.On("RowsAffected").Return(int64(3), nil)
	mockDB.NamedExecReturns(mockResult, nil)
	res, err = fabDB.NamedExec("", "", nil)
	gt.Expect(err).NotTo(HaveOccurred())

	rows, err = res.RowsAffected()
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(rows).To(Equal(int64(3)))

	mockDB.NamedExecReturns(nil, errors.New("NamedExec Error"))
	res, err = fabDB.NamedExec("", "", nil)
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("NamedExec Error"))

	// Get
	mockDB.GetReturns(nil)
	err = fabDB.Get("", nil, "")
	gt.Expect(err).NotTo(HaveOccurred())

	mockDB.GetReturns(errors.New("Get Error"))
	err = fabDB.Get("", nil, "")
	gt.Expect(err.Error()).To(Equal("Get Error"))

	// Queryx
	mockDB.QueryxReturns(&sqlx.Rows{}, nil)
	r, err := fabDB.Queryx("", "")
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(r).NotTo(BeNil())

	mockDB.QueryxReturns(nil, errors.New("Queryx Error"))
	_, err = fabDB.Queryx("", "")
	gt.Expect(err.Error()).To(Equal("Queryx Error"))

	// DriverName
	mockDB.DriverNameReturns("sqlite3")
	driverName := fabDB.DriverName()
	gt.Expect(driverName).To(Equal("sqlite3"))

	// Rebind
	mockDB.RebindReturns("Select * from")
	query := fabDB.Rebind("")
	gt.Expect(query).To(Equal("Select * from"))
}

func TestCurrentDBLevels(t *testing.T) {
	gt := NewGomegaWithT(t)

	mockFabricCADB := &mocks.FabricCADB{}
	mockFabricCADB.GetReturns(errors.New("failed to get levels"))

	_, err := db.CurrentDBLevels(mockFabricCADB)
	gt.Expect(err).To(HaveOccurred())
	gt.Expect(err.Error()).To(Equal("failed to get levels"))

	mockFabricCADB = &mocks.FabricCADB{}
	levels, err := db.CurrentDBLevels(mockFabricCADB)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(levels).To(Equal(&util.Levels{}))
}
