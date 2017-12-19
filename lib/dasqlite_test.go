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

package lib_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	. "github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/dbutil"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

const (
	dbPath = "/tmp/dbtesting"

	sqliteTruncateTables = `
DELETE FROM Users;
DELETE FROM affiliations;
`

	rootDB = "rootDir/fabric_ca.db"
)

type TestAccessor struct {
	Accessor *Accessor
	DB       *sqlx.DB
}

func (ta *TestAccessor) Truncate() {
	Truncate(ta.DB)
}

func TestSQLite(t *testing.T) {
	cleanTestSlateSQ(t)
	defer cleanTestSlateSQ(t)

	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dbPath, 0755)
		}
	} else {
		err = os.RemoveAll(dbPath)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		os.MkdirAll(dbPath, 0755)
	}
	dataSource := dbPath + "/fabric-ca.db"
	db, err := dbutil.NewUserRegistrySQLLite3(dataSource)
	if err != nil {
		t.Error("Failed to open connection to DB")
	}
	accessor := NewDBAccessor(db)

	ta := TestAccessor{
		Accessor: accessor,
		DB:       db,
	}
	testEverything(ta, t)
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

func TestEmptyAccessor(t *testing.T) {
	a := &Accessor{}
	ui := spi.UserInfo{}
	err := a.InsertUser(nil)
	if err == nil {
		t.Error("Passing in nil should have resulted in an error")
	}

	err = a.InsertUser(&ui)
	if err == nil {
		t.Error("Empty Accessor InsertUser should have failed")
	}
}

func TestDBCreation(t *testing.T) {
	cleanTestSlateSQ(t)
	defer cleanTestSlateSQ(t)

	os.Mkdir(rootDir, 0755)

	testWithExistingDbAndTablesAndUser(t)
	testWithExistingDbAndTable(t)
	testWithExistingDb(t)
}

func createSQLiteDB(path string, t *testing.T) (*sqlx.DB, *TestAccessor) {
	db, err := sqlx.Open("sqlite3", path)
	assert.NoError(t, err, "Failed to open SQLite database")

	accessor := NewDBAccessor(db)

	ta := &TestAccessor{
		Accessor: accessor,
		DB:       db,
	}

	return db, ta
}

// Test that an already bootstrapped database properly get inspected and bootstrapped with any new identities on the
// next server start
func testWithExistingDbAndTablesAndUser(t *testing.T) {
	var err error

	err = os.RemoveAll(rootDB)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	db, acc := createSQLiteDB(rootDB, t)

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(64), token bytea, type VARCHAR(64), affiliation VARCHAR(64), attributes VARCHAR(256), state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0)")
	assert.NoError(t, err, "Error creating users table")

	srv := TestGetServer2(false, rootPort, rootDir, "", -1, t)
	srv.CA.Config.DB.Datasource = "fabric_ca.db"

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

	// Add additional user to registry and start server and confirm that it correctly get added
	srv.RegisterBootstrapUser("admin2", "admin2pw", "")

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	_, err = acc.Accessor.GetUser("admin2", nil)
	assert.NoError(t, err, "Failed to correctly insert 'admin2' during second server bootstrap")

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

	err = db.Close()
	assert.NoError(t, err, "Failed to close DB")
}

// Test starting a server with an already existing database and tables, but not bootstrapped
func testWithExistingDbAndTable(t *testing.T) {
	var err error

	err = os.RemoveAll(rootDB)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	db, acc := createSQLiteDB(rootDB, t)

	srv := TestGetServer2(false, rootPort, rootDir, "", -1, t)
	srv.CA.Config.DB.Datasource = "fabric_ca.db"

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id VARCHAR(64), token bytea, type VARCHAR(64), affiliation VARCHAR(64), attributes VARCHAR(256), state INTEGER,  max_enrollments INTEGER, level INTEGER DEFAULT 0)")
	assert.NoError(t, err, "Error creating users table")

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	_, err = acc.Accessor.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to correctly insert 'admin' during second server bootstrap")

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

	err = db.Close()
	assert.NoError(t, err, "Failed to close DB")
}

// Test starting a server with an already existing database, but no tables or users
func testWithExistingDb(t *testing.T) {
	var err error

	err = os.RemoveAll(rootDB)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	db, acc := createSQLiteDB(rootDB, t)

	srv := TestGetServer2(false, rootPort, rootDir, "", -1, t)
	srv.CA.Config.DB.Datasource = "fabric_ca.db"

	err = srv.Start()
	assert.NoError(t, err, "Failed to start server")

	_, err = acc.Accessor.GetUser("admin", nil)
	assert.NoError(t, err, "Failed to correctly insert 'admin' during second server bootstrap")

	err = srv.Stop()
	assert.NoError(t, err, "Failed to stop server")

	err = db.Close()
	assert.NoError(t, err, "Failed to close DB")
}

func cleanTestSlateSQ(t *testing.T) {
	err := os.RemoveAll(rootDir)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
	err = os.RemoveAll(dbPath)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
}

func testEverything(ta TestAccessor, t *testing.T) {
	testInsertAndGetUser(ta, t)
	testModifyAttribute(ta, t)
	testDeleteUser(ta, t)
	testUpdateUser(ta, t)
	testInsertAndGetAffiliation(ta, t)
	testDeleteAffiliation(ta, t)
}

func testInsertAndGetUser(ta TestAccessor, t *testing.T) {
	t.Log("TestInsertAndGetUser")
	ta.Truncate()

	insert := spi.UserInfo{
		Name: "testId",
		Pass: "123456",
		Type: "client",
		Attributes: []api.Attribute{
			api.Attribute{
				Name:  "hf.Registrar.Roles",
				Value: "peer,client,orderer,user",
			},
			api.Attribute{
				Name:  "hf.Revoker",
				Value: "false",
			},
			api.Attribute{
				Name:  "hf.Registrar.Attributes",
				Value: "*",
			},
			api.Attribute{
				Name:  "xyz",
				Value: "xyz",
			},
		},
	}

	err := ta.Accessor.InsertUser(&insert)
	if err != nil {
		t.Errorf("Error occured during insert query of ID: %s, error: %s", insert.Name, err)
	}

	user, err := ta.Accessor.GetUser(insert.Name, nil)
	if err != nil {
		t.Errorf("Error occured during querying of id: %s, error: %s", insert.Name, err)
	}

	if user.GetName() != insert.Name {
		t.Error("Incorrect ID retrieved")
	}
}

func testModifyAttribute(ta TestAccessor, t *testing.T) {

	user, err := ta.Accessor.GetUser("testId", nil)
	assert.NoError(t, err, "Failed to get user")

	err = user.ModifyAttributes([]api.Attribute{
		api.Attribute{
			Name:  "hf.Registrar.Roles",
			Value: "peer",
		},
		api.Attribute{
			Name:  "hf.Revoker",
			Value: "",
		},
		api.Attribute{
			Name:  "xyz",
			Value: "",
		},
		api.Attribute{
			Name:  "hf.IntermediateCA",
			Value: "true",
		},
	})
	assert.NoError(t, err, "Failed to modify user's attributes")

	user, err = ta.Accessor.GetUser("testId", nil)
	assert.NoError(t, err, "Failed to get user")

	_, err = user.GetAttribute("hf.Revoker")
	assert.Error(t, err, "Should have returned an error, attribute should have been deleted")

	// Removes last attribute in the slice, should have correctly removed it
	_, err = user.GetAttribute("xyz")
	assert.Error(t, err, "Should have returned an error, attribute should have been deleted")

	attr, err := user.GetAttribute("hf.IntermediateCA")
	assert.NoError(t, err, "Failed to add attribute")
	assert.Equal(t, "true", attr.Value, "Incorrect value for attribute 'hf.IntermediateCA")

	attr, err = user.GetAttribute("hf.Registrar.Roles")
	assert.NoError(t, err, "Failed to get attribute")
	assert.Equal(t, "peer", attr.Value, "Incorrect value for attribute 'hf.Registrar.Roles")

	// Test to make sure that any existing attributes that were not modified continue to exist in there original state
	attr, err = user.GetAttribute("hf.Registrar.Attributes")
	assert.NoError(t, err, "Failed to get attribute")
	assert.Equal(t, "*", attr.Value)
}

func testDeleteUser(ta TestAccessor, t *testing.T) {
	t.Log("TestDeleteUser")
	ta.Truncate()

	insert := spi.UserInfo{
		Name:       "testId",
		Pass:       "123456",
		Type:       "client",
		Attributes: []api.Attribute{},
	}

	err := ta.Accessor.InsertUser(&insert)
	if err != nil {
		t.Errorf("Error occured during insert query of id: %s, error: %s", insert.Name, err)
	}

	_, err = ta.Accessor.DeleteUser(insert.Name)
	if err != nil {
		t.Errorf("Error occured during deletion of ID: %s, error: %s", insert.Name, err)
	}

	_, err = ta.Accessor.GetUser(insert.Name, nil)
	if err == nil {
		t.Error("Should have errored, and not returned any results")
	}
}

func testUpdateUser(ta TestAccessor, t *testing.T) {
	t.Log("TestUpdateUser")
	ta.Truncate()

	insert := spi.UserInfo{
		Name:           "testId",
		Pass:           "123456",
		Type:           "client",
		Attributes:     []api.Attribute{},
		MaxEnrollments: 1,
	}

	err := ta.Accessor.InsertUser(&insert)
	if err != nil {
		t.Errorf("Error occured during insert query of ID: %s, error: %s", insert.Name, err)
	}

	insert.Pass = "654321"

	err = ta.Accessor.UpdateUser(nil, true)
	if err == nil {
		t.Error("Passing in nil should have resulted in an error")
	}

	err = ta.Accessor.UpdateUser(&insert, true)
	if err != nil {
		t.Errorf("Error occured during update query of ID: %s, error: %s", insert.Name, err)
	}

	user, err := ta.Accessor.GetUser(insert.Name, nil)
	if err != nil {
		t.Errorf("Error occured during querying of ID: %s, error: %s", insert.Name, err)
	}

	err = user.Login(insert.Pass, -1)
	if err != nil {
		t.Error("Failed to login in user: ", err)
	}

}

func testInsertAndGetAffiliation(ta TestAccessor, t *testing.T) {
	ta.Truncate()

	err := ta.Accessor.InsertAffiliation("Bank1", "Banks", 0)
	if err != nil {
		t.Errorf("Error occured during insert query of group: %s, error: %s", "Bank1", err)
	}

	group, err := ta.Accessor.GetAffiliation("Bank1")
	if err != nil {
		t.Errorf("Error occured during querying of name: %s, error: %s", "Bank1", err)
	}

	if group.GetName() != "Bank1" {
		t.Error("Failed to query")
	}

}

func testDeleteAffiliation(ta TestAccessor, t *testing.T) {
	ta.Truncate()

	err := ta.Accessor.InsertAffiliation("Banks.Bank2", "Banks", 0)
	if err != nil {
		t.Errorf("Error occured during insert query of group: %s, error: %s", "Bank2", err)
	}

	_, err = ta.Accessor.DeleteAffiliation("Banks.Bank2", true, true, true)
	if err != nil {
		t.Errorf("Error occured during deletion of group: %s, error: %s", "Bank2", err)
	}

	_, err = ta.Accessor.GetAffiliation("Banks.Bank2")
	if err == nil {
		t.Error("Should have errored, and not returned any results")
	}
}

func TestDBErrorMessages(t *testing.T) {
	var err error

	cleanTestSlateSQ(t)
	defer cleanTestSlateSQ(t)

	if _, err = os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dbPath, 0755)
		}
	} else {
		err = os.RemoveAll(dbPath)
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		os.MkdirAll(dbPath, 0755)
	}

	dataSource := dbPath + "/fabric-ca.db"
	db, err := dbutil.NewUserRegistrySQLLite3(dataSource)
	if err != nil {
		t.Error("Failed to open connection to DB")
	}

	accessor := NewDBAccessor(db)

	ta := TestAccessor{
		Accessor: accessor,
		DB:       db,
	}

	expectedErr := "Failed to get %s"
	_, err = ta.Accessor.GetAffiliation("hyperledger")
	if assert.Error(t, err, "Should have errored, and not returned any results") {
		assert.Contains(t, err.Error(), fmt.Sprintf(expectedErr, "Affiliation"))
	}

	_, err = ta.Accessor.GetUser("testuser", []string{})
	if assert.Error(t, err, "Should have errored, and not returned any results") {
		assert.Contains(t, err.Error(), fmt.Sprintf(expectedErr, "User"))
	}

	newCertDBAcc := NewCertDBAccessor(db, 0)
	_, err = newCertDBAcc.GetCertificateWithID("serial", "aki")
	if assert.Error(t, err, "Should have errored, and not returned any results") {
		assert.Contains(t, err.Error(), fmt.Sprintf(expectedErr, "Certificate"))
	}
}
