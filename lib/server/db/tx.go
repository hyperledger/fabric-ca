/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

//go:generate counterfeiter -o mocks/fabricCATX.go -fake-name FabricCATx . FabricCATx

// FabricCATx is the interface with functions implemented by sqlx.Tx
// object that are used by Fabric CA server
type FabricCATx interface {
	SqlxTx
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

// TX is the database transaction
type TX struct {
	TX SqlxTx
}

// Select performs select sql statement
func (tx *TX) Select(dest interface{}, query string, args ...interface{}) error {
	return tx.TX.Select(dest, query, args...)
}

// Exec executes query
func (tx *TX) Exec(query string, args ...interface{}) (sql.Result, error) {
	return tx.TX.Exec(query, args...)
}

// Get executes query
func (tx *TX) Get(dest interface{}, query string, args ...interface{}) error {
	return tx.TX.Get(dest, query, args...)
}

// Queryx executes query
func (tx *TX) Queryx(query string, args ...interface{}) (*sqlx.Rows, error) {
	return tx.TX.Queryx(query, args...)
}

// Rebind rebinds the query
func (tx *TX) Rebind(query string) string {
	return tx.TX.Rebind(query)
}

// Commit commits the transaction
func (tx *TX) Commit() error {
	return tx.TX.Commit()
}

// Rollback roll backs the transaction
func (tx *TX) Rollback() error {
	return tx.TX.Rollback()
}
