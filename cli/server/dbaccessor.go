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
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"

	"github.com/jmoiron/sqlx"
	"github.com/kisielk/sqlstruct"
	_ "github.com/mattn/go-sqlite3" // Needed to support sqlite
)

// Match to sqlx
func init() {
	sqlstruct.TagName = "db"
}

const (
	insertUser = `
INSERT INTO Users (id, enrollment_id, token, type, metadata, state, serial_number)
	VALUES (:id, :enrollment_id, :token, :type, :metadata, :state, :serial_number);`

	deleteUser = `
DELETE FROM Users
	WHERE (id = ?);`

	updateUser = `
UPDATE Users
	SET token = :token, metadata = :metadata, state = :state
	WHERE (id = :id);`

	getUser = `
SELECT * FROM Users
	WHERE (id = ?)`

	insertGroup = `
INSERT INTO Groups (name, parent_id)
	VALUES ($1, $2)`

	deleteGroup = `
DELETE FROM Groups
	WHERE (name = ?)`

	getGroup = `
SELECT * FROM Groups
	WHERE (name = ?)`
)

// Accessor implements db.Accessor interface.
type Accessor struct {
	db *sqlx.DB
}

// Group defines a group name and its parent
type Group struct {
	Name     string `db:"name"`
	ParentID string `db:"parent_id"`
}

func (d *Accessor) checkDB() error {
	if d.db == nil {
		return errors.New("unknown db object, please check SetDB method")
	}
	return nil
}

// NewDBAccessor is a constructor for the database API
func NewDBAccessor() *Accessor {
	return &Accessor{}
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *Accessor) SetDB(db *sqlx.DB) {
	d.db = db
	return
}

// InsertUser inserts user into database
func (d *Accessor) InsertUser(user cop.UserRecord) error {
	log.Debugf("DB: Insert User (%s) to database", user.ID)
	err := d.checkDB()
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(insertUser, &cop.UserRecord{
		ID:           user.ID,
		EnrollmentID: user.EnrollmentID,
		Token:        user.Token,
		Type:         user.Type,
		Metadata:     user.Metadata,
		State:        user.State,
		SerialNumber: user.SerialNumber,
	})

	if err != nil {
		log.Error("Error during inserting of user, error: ", err)
		return err
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if numRowsAffected == 0 {
		msg := "Failed to insert the user record"
		log.Error(msg)
		return cop.NewError(cop.UserStoreError, msg)
	}

	if numRowsAffected != 1 {
		msg := fmt.Sprintf("%d rows are affected, should be 1 row", numRowsAffected)
		log.Error(msg)
		return cop.NewError(cop.UserStoreError, msg)
	}

	log.Debug("User inserted into database successfully")
	return nil

}

// DeleteUser deletes user from database
func (d *Accessor) DeleteUser(id string) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.db.Exec(deleteUser, id)
	if err != nil {
		return err
	}

	return nil
}

// UpdateUser updates user in database
func (d *Accessor) UpdateUser(user cop.UserRecord) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(updateUser, &cop.UserRecord{
		ID:       user.ID,
		Token:    user.Token,
		State:    user.State,
		Metadata: user.Metadata,
	})

	if err != nil {
		return err
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return cop.NewError(cop.UserStoreError, "failed to update the user record")
	}

	if numRowsAffected != 1 {
		return cop.NewError(cop.UserStoreError, "%d rows are affected, should be 1 row", numRowsAffected)
	}

	return err

}

// GetUser gets user from database
func (d *Accessor) GetUser(id string) (cop.UserRecord, error) {
	err := d.checkDB()
	var User cop.UserRecord
	if err != nil {
		return User, err
	}

	err = d.db.Get(&User, d.db.Rebind(getUser), id)
	if err != nil {
		return User, err
	}

	return User, nil
}

// InsertGroup inserts group into database
func (d *Accessor) InsertGroup(name string, parentID string) error {
	log.Debugf("DB - Insert Group (%s)", name)
	err := d.checkDB()
	if err != nil {
		return err
	}
	_, err = d.db.Exec(insertGroup, name, parentID)
	if err != nil {
		return err
	}

	return nil
}

// DeleteGroup deletes group from database
func (d *Accessor) DeleteGroup(name string) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	_, err = d.db.Exec(deleteGroup, name)
	if err != nil {
		return err
	}

	return nil
}

// GetGroup gets group from database
func (d *Accessor) GetGroup(name string) (string, string, error) {
	log.Debugf("DB - Get Group (%s)", name)
	err := d.checkDB()
	if err != nil {
		return "", "", err
	}

	group := Group{}
	err = d.db.Get(&group, d.db.Rebind(getGroup), name)
	if err != nil {
		return "", "", err
	}

	return group.Name, group.ParentID, err
}
