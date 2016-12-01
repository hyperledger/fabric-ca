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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/cli/server/spi"
	"github.com/hyperledger/fabric-cop/idp"

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
INSERT INTO users (id, token, type, user_group, attributes, state, max_enrollments, serial_number, authority_key_identifier)
	VALUES (:id, :token, :type, :user_group, :attributes, :state, :max_enrollments, :serial_number, :authority_key_identifier);`

	deleteUser = `
DELETE FROM users
	WHERE (id = ?);`

	updateUser = `
UPDATE users
	SET token = :token, type = :type, user_group = :user_group, attributes = :attributes
	WHERE (id = :id);`

	getUser = `
SELECT * FROM users
	WHERE (id = ?)`

	insertGroup = `
INSERT INTO groups (name, parent_id)
	VALUES (?, ?)`

	deleteGroup = `
DELETE FROM groups
	WHERE (name = ?)`

	getGroup = `
SELECT name, parent_id FROM groups
	WHERE (name = ?)`
)

const (
	serialNumber = iota
	aki
	prekey
	maxEnrollments
	state
)

// UserRecord defines the properties of a user
type UserRecord struct {
	Name           string `db:"id"`
	Pass           string `db:"token"`
	Type           string `db:"type"`
	Group          string `db:"user_group"`
	Attributes     string `db:"attributes"`
	State          int    `db:"state"`
	MaxEnrollments int    `db:"max_enrollments"`
	SerialNumber   string `db:"serial_number"`
	AKI            string `db:"authority_key_identifier"`
}

// GroupRecord defines the properties of a group
type GroupRecord struct {
	Name     string `db:"name"`
	ParentID string `db:"parent_id"`
	Prekey   string `db:"prekey"`
}

// Accessor implements db.Accessor interface.
type Accessor struct {
	db *sqlx.DB
}

// NewDBAccessor is a constructor for the database API
func NewDBAccessor() *Accessor {
	return &Accessor{}
}

func (d *Accessor) checkDB() error {
	if d.db == nil {
		return errors.New("unknown db object, please check SetDB method")
	}
	return nil
}

// SetDB changes the underlying sql.DB object Accessor is manipulating.
func (d *Accessor) SetDB(db *sqlx.DB) {
	d.db = db
	return
}

// LoginUserBasicAuth checks to see valid credentials have been provided
func (d *Accessor) LoginUserBasicAuth(user, pass string) (spi.User, error) {
	log.Debugf("DB: Login user authentication for %s", user)

	var userRec UserRecord
	err := d.db.Get(&userRec, d.db.Rebind(getUser), user)
	if err != nil {
		log.Errorf("User (%s) not registered [error: %s]", user, err)
		return nil, cop.NewError(cop.AuthorizationFailure, "User (%s) not registered [error: %s]", user, err)
	}

	userInfo := convertToUserInfo(&userRec)

	if userRec.Pass == pass {
		if userRec.State >= 0 && userRec.State < userRec.MaxEnrollments {
			state := userRec.State + 1
			res, err := d.db.Exec("UPDATE users SET state = ? WHERE (id = ?)", state, user)
			if err != nil {
				return nil, err
			}

			numRowsAffected, err := res.RowsAffected()

			if err != nil {
				return nil, err
			}

			if numRowsAffected == 0 {
				return nil, cop.NewError(cop.UserStoreError, "Failed to update the user record")
			}

			if numRowsAffected != 1 {
				return nil, cop.NewError(cop.UserStoreError, "%d rows are affected, should be 1 row", numRowsAffected)
			}

			return userInfo, nil
		}
		_, err := d.db.Exec("UPDATE users SET token = ? WHERE (id = ?)", "", user)
		if err != nil {
			return nil, err
		}
		log.Errorf("User (%s) has already been enrolled", user)
		return nil, cop.NewError(cop.AuthorizationFailure, "User has already been enrolled")
	}

	log.Errorf("Incorrect username/password provided")
	return nil, cop.NewError(cop.AuthorizationFailure, "Incorrect username/password provided)")
}

// InsertUser inserts user into database
func (d *Accessor) InsertUser(user spi.UserInfo) error {
	log.Debugf("DB: Insert User (%s) to database", user.Name)

	err := d.checkDB()
	if err != nil {
		return err
	}

	attrBytes, err := json.Marshal(user.Attributes)
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(insertUser, &UserRecord{
		Name:       user.Name,
		Pass:       user.Pass,
		Type:       user.Type,
		Group:      user.Group,
		Attributes: string(attrBytes),
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

	log.Debugf("User %s inserted into database successfully", user.Name)

	return nil

}

// DeleteUser deletes user from database
func (d *Accessor) DeleteUser(id string) error {
	log.Debugf("DB: Delete User (%s)", id)
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
func (d *Accessor) UpdateUser(user spi.UserInfo) error {
	log.Debugf("DB: Update User (%s) in database", user.Name)
	err := d.checkDB()
	if err != nil {
		return err
	}

	attributes, err := json.Marshal(user.Attributes)
	if err != nil {
		return err
	}

	res, err := d.db.NamedExec(updateUser, &UserRecord{
		Name:       user.Name,
		Pass:       user.Pass,
		Type:       user.Type,
		Group:      user.Group,
		Attributes: string(attributes),
	})

	if err != nil {
		log.Errorf("Failed to update user record [error: %s]", err)
		return err
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return cop.NewError(cop.UserStoreError, "Failed to update the user record")
	}

	if numRowsAffected != 1 {
		return cop.NewError(cop.UserStoreError, "%d rows are affected, should be 1 row", numRowsAffected)
	}

	return err

}

// UpdateField updates a specific field in database
func (d *Accessor) UpdateField(id string, field int, value interface{}) error {
	err := d.checkDB()
	if err != nil {
		return err
	}

	switch field {
	case serialNumber:
		log.Debug("Update serial number")
		val := value.(string)
		_, err = d.db.Exec("UPDATE users SET serial_number = ? WHERE (id = ?)", val, id)
		if err != nil {
			return err
		}
	case aki:
		log.Debug("Update authority key idenitifier")
		val := value.(string)
		_, err = d.db.Exec("UPDATE users SET authority_key_identifier = ? WHERE (id = ?)", val, id)
		if err != nil {
			return err
		}
	case maxEnrollments:
		log.Debug("Update max enrollments")
		val := value.(int)
		_, err = d.db.Exec("UPDATE users SET max_enrollments = ? WHERE (id = ?)", val, id)
		if err != nil {
			log.Error(err)
			return err
		}
	case state:
		log.Debug("Update state")
		val := value.(int)
		_, err = d.db.Exec("UPDATE users SET state = ? WHERE (id = ?)", val, id)
		if err != nil {
			log.Error(err)
			return err
		}
	default:
		log.Error("DB: Specified field does not exist or cannot be updated")
		return cop.NewError(cop.DatabaseError, "DB: Specified field does not exist or cannot be updated")
	}

	return err
}

// GetField updates a specific field in database
func (d *Accessor) GetField(id string, field int) (interface{}, error) {
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	switch field {
	case prekey:
		log.Debug("Get prekey")
		var groupRec GroupRecord
		err = d.db.Get(&groupRec, "SELECT prekey FROM groups WHERE (name = ?)", id)
		if err != nil {
			return nil, err
		}
		return groupRec.Prekey, nil
	case serialNumber:
		log.Debug("Get serial number")
		var userRec UserRecord
		err = d.db.Get(&userRec, "SELECT serial_number FROM users WHERE (id = ?)", id)
		if err != nil {
			return nil, err
		}
		return userRec.SerialNumber, nil
	case aki:
		log.Debug("Get authority key idenitifier")
		var userRec UserRecord
		err = d.db.Get(&userRec, "SELECT authority_key_identifier FROM users WHERE (id = ?)", id)
		if err != nil {
			return nil, err
		}
		return userRec.AKI, nil
	default:
		log.Error("DB: Specified field does not exist or cannot be retrieved")
		return nil, cop.NewError(cop.DatabaseError, "DB: Specified field does not exist or cannot be retrieved")
	}

}

// GetUser gets user from database
func (d *Accessor) GetUser(id string) (spi.User, error) {
	log.Debugf("DB: Get User (%s) from database", id)

	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var userRec UserRecord
	err = d.db.Get(&userRec, d.db.Rebind(getUser), id)
	if err != nil {
		return nil, err
	}

	userInfo := convertToUserInfo(&userRec)

	return userInfo, nil
}

// InsertGroup inserts group into database
func (d *Accessor) InsertGroup(name string, parentID string) error {
	log.Debugf("DB: Insert Group (%s)", name)
	err := d.checkDB()
	if err != nil {
		return err
	}
	_, err = d.db.Exec(d.db.Rebind(insertGroup), name, parentID)
	if err != nil {
		return err
	}

	/*
		preKeyString := crypto.CreateRootPreKey()

		_, err = d.db.Exec("UPDATE groups SET prekey = ? WHERE (name = ?)", preKeyString, name)
		if err != nil {
			return err
		}
	*/

	return nil
}

// DeleteGroup deletes group from database
func (d *Accessor) DeleteGroup(name string) error {
	log.Debugf("DB: Delete Group (%s)", name)
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
func (d *Accessor) GetGroup(name string) (spi.Group, error) {
	log.Debugf("DB: Get Group (%s)", name)
	err := d.checkDB()
	if err != nil {
		return nil, err
	}

	var groupInfo spi.GroupInfo

	err = d.db.Get(&groupInfo, d.db.Rebind(getGroup), name)
	if err != nil {
		return nil, err
	}

	return &groupInfo, nil
}

// GetRootGroup gets root group from database
func (d *Accessor) GetRootGroup() (spi.Group, error) {
	log.Debugf("DB: Get root group")
	err := d.checkDB()
	if err != nil {
		return nil, err
	}
	// TODO: IMPLEMENT
	return nil, nil
}

func convertToUserInfo(userRec *UserRecord) *spi.UserInfo {
	var userInfo = new(spi.UserInfo)
	userInfo.Name = userRec.Name
	userInfo.Pass = userRec.Pass
	userInfo.Type = userRec.Type

	var attributes []idp.Attribute
	json.Unmarshal([]byte(userRec.Attributes), &attributes)
	userInfo.Attributes = attributes

	return userInfo
}
