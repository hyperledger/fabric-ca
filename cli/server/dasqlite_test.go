/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"os"
	"strings"
	"testing"

	api "github.com/hyperledger/fabric-cop/api"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPath = "/tmp/dbtesting"

	sqliteTruncateTables = `
DELETE FROM Users;
DELETE FROM Groups;
`
)

type TestAccessor struct {
	Accessor *Accessor
	DB       *sqlx.DB
}

func (ta *TestAccessor) Truncate() {
	Truncate(ta.DB)
}

func TestSQLite(t *testing.T) {
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dbPath, 0755)
		}
	} else {
		os.RemoveAll(dbPath)
		os.MkdirAll(dbPath, 0755)
	}

	var cfg Config
	cfg.DBdriver = "sqlite3"
	cfg.DataSource = dbPath + "/cop.db"
	db, err := GetDB(&cfg)

	if err != nil {
		t.Error(err)
	}
	ta := TestAccessor{
		Accessor: NewDBAccessor(),
		DB:       db,
	}
	ta.Accessor.SetDB(db)
	testEverything(ta, t)
	removeDatabase()
}

// Truncate truncates the DB
func Truncate(db *sqlx.DB) {
	var sql []string
	sql = []string{sqliteTruncateTables}

	for _, expr := range sql {
		if len(strings.TrimSpace(expr)) == 0 {
			continue
		}
		if _, err := db.Exec(expr); err != nil {
			panic(err)
		}
	}
}

func removeDatabase() {
	os.RemoveAll(dbPath)
}

func testEverything(ta TestAccessor, t *testing.T) {
	testInsertAndGetUser(ta, t)
	testDeleteUser(ta, t)
	testUpdateUser(ta, t)
	testInsertAndGetGroup(ta, t)
	testDeleteGroup(ta, t)
}

func testInsertAndGetUser(ta TestAccessor, t *testing.T) {
	t.Log("TestInsertAndGetUser")
	ta.Truncate()

	insert := api.UserRecord{
		ID:           "testId",
		EnrollmentID: "testId//IBM",
		Token:        "123456",
		Metadata:     "",
		State:        0,
	}

	err := ta.Accessor.InsertUser(insert)
	if err != nil {
		t.Errorf("Error occured during insert query of ID: %s, error: %s", insert.ID, err)
	}

	result, err := ta.Accessor.GetUser(insert.ID)

	if err != nil {
		t.Errorf("Error occured during querying of id: %s, error: %s", insert.ID, err)
	}
	if result.ID == "" {
		t.Error("No results returned")
	}
	if result.ID != insert.ID {
		t.Error("Incorrect ID retrieved")
	}
}

func testDeleteUser(ta TestAccessor, t *testing.T) {
	t.Log("TestDeleteUser")
	ta.Truncate()

	insert := api.UserRecord{
		ID:           "deleteID",
		EnrollmentID: "deleteID//IBM",
		Token:        "123456",
		Metadata:     "",
		State:        0,
	}

	err := ta.Accessor.InsertUser(insert)
	if err != nil {
		t.Errorf("Error occured during insert query of id: %s, error: %s", insert.ID, err)
	}

	err = ta.Accessor.DeleteUser(insert.ID)
	if err != nil {
		t.Errorf("Error occured during deletion of ID: %s, error: %s", insert.ID, err)
	}

	_, err = ta.Accessor.GetUser(insert.ID)
	if err == nil {
		t.Error("Should have errored, and not returned any results")
	}
}

func testUpdateUser(ta TestAccessor, t *testing.T) {
	t.Log("TestUpdateUser")
	ta.Truncate()

	insert := api.UserRecord{
		ID:           "testID",
		EnrollmentID: "testId//IBM",
		Token:        "123456",
		Metadata:     "",
		State:        0,
	}
	err := ta.Accessor.InsertUser(insert)
	if err != nil {
		t.Errorf("Error occured during insert query of ID: %s, error: %s", insert.ID, err)
	}

	insert.Token = "654321"

	ta.Accessor.UpdateUser(insert)
	if err != nil {
		t.Errorf("Error occured during update query of ID: %s, error: %s", insert.ID, err)
	}

	result, err := ta.Accessor.GetUser(insert.ID)
	if err != nil {
		t.Errorf("Error occured during querying of ID: %s, error: %s", insert.ID, err)
	}

	if result.Token != insert.Token {
		t.Error("Failed to update user")
	}

}

func testInsertAndGetGroup(ta TestAccessor, t *testing.T) {
	ta.Truncate()

	err := ta.Accessor.InsertGroup("Bank1", "Banks")
	if err != nil {
		t.Errorf("Error occured during insert query of group: %s, error: %s", "Bank1", err)
	}

	name, parentID, err := ta.Accessor.GetGroup("Bank1")
	if err != nil {
		t.Errorf("Error occured during querying of name: %s, error: %s", "Bank1", err)
	}

	if name != "Bank1" || parentID != "Banks" {
		t.Error("Failed to query")
	}
}

func testDeleteGroup(ta TestAccessor, t *testing.T) {
	ta.Truncate()

	err := ta.Accessor.InsertGroup("Bank2", "Banks")
	if err != nil {
		t.Errorf("Error occured during insert query of group: %s, error: %s", "Bank2", err)
	}

	err = ta.Accessor.DeleteGroup("Bank2")
	if err != nil {
		t.Errorf("Error occured during deletion of group: %s, error: %s", "Bank2", err)
	}

	_, _, err = ta.Accessor.GetGroup("Bank2")
	if err == nil {
		t.Error("Should have errored, and not returned any results")
	}
}
