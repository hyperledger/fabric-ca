/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
)

//go:generate counterfeiter -o mocks/fabricCATX.go -fake-name FabricCATx . FabricCATx

// FabricCATx is the interface with functions implemented by sqlx.Tx
// object that are used by Fabric CA server
type FabricCATx interface {
	Select(funcName string, dest interface{}, query string, args ...interface{}) error
	Exec(funcName, query string, args ...interface{}) (sql.Result, error)
	Queryx(funcName, query string, args ...interface{}) (*sqlx.Rows, error)
	Get(funcName string, dest interface{}, query string, args ...interface{}) error
	Rebind(query string) string
	Commit(funcName string) error
	Rollback(funcName string) error
}

//go:generate counterfeiter -o mocks/sqlxTx.go -fake-name SqlxTx . SqlxTx

// SqlxTx is the contract with sqlx
type SqlxTx interface {
	Queryx(query string, args ...interface{}) (*sqlx.Rows, error)
	Get(dest interface{}, query string, args ...interface{}) error
	Select(dest interface{}, query string, args ...interface{}) error
	Rebind(query string) string
	Exec(query string, args ...interface{}) (sql.Result, error)
	Commit() error
	Rollback() error
}

type record interface {
	recordMetric(startTime time.Time, funcName, dbapiName string)
}

// TX is the database transaction
type TX struct {
	TX     SqlxTx
	Record record
}

// Select performs select sql statement
func (tx *TX) Select(funcName string, dest interface{}, query string, args ...interface{}) error {
	startTime := time.Now()
	err := tx.TX.Select(dest, query, args...)
	tx.Record.recordMetric(startTime, funcName, "Select")
	return err
}

// Exec executes query
func (tx *TX) Exec(funcName, query string, args ...interface{}) (sql.Result, error) {
	startTime := time.Now()
	res, err := tx.TX.Exec(query, args...)
	tx.Record.recordMetric(startTime, funcName, "Exec")
	return res, err
}

// Get executes query
func (tx *TX) Get(funcName string, dest interface{}, query string, args ...interface{}) error {
	startTime := time.Now()
	err := tx.TX.Get(dest, query, args...)
	tx.Record.recordMetric(startTime, funcName, "Get")
	return err
}

// Queryx executes query
func (tx *TX) Queryx(funcName, query string, args ...interface{}) (*sqlx.Rows, error) {
	startTime := time.Now()
	rows, err := tx.TX.Queryx(query, args...)
	tx.Record.recordMetric(startTime, funcName, "Queryx")
	return rows, err
}

// Rebind rebinds the query
func (tx *TX) Rebind(query string) string {
	return tx.TX.Rebind(query)
}

// Commit commits the transaction
func (tx *TX) Commit(funcName string) error {
	startTime := time.Now()
	err := tx.TX.Commit()
	tx.Record.recordMetric(startTime, funcName, "Commit")
	return err
}

// Rollback roll backs the transaction
func (tx *TX) Rollback(funcName string) error {
	startTime := time.Now()
	err := tx.TX.Rollback()
	tx.Record.recordMetric(startTime, funcName, "Rollback")
	return err
}
