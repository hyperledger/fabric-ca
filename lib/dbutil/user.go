/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dbutil

import (
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// UserRecord defines the properties of a user
type UserRecord struct {
	Name                      string `db:"id"`
	Pass                      []byte `db:"token"`
	Type                      string `db:"type"`
	Affiliation               string `db:"affiliation"`
	Attributes                string `db:"attributes"`
	State                     int    `db:"state"`
	MaxEnrollments            int    `db:"max_enrollments"`
	Level                     int    `db:"level"`
	IncorrectPasswordAttempts int    `db:"incorrect_password_attempts"`
}

// User is the databases representation of a user
type User struct {
	spi.UserInfo
	pass  []byte
	attrs map[string]api.Attribute
	db    *DB
}

// NewDBUser creates a DBUser object from the DB user record
func NewDBUser(userRec *UserRecord, db *DB) *User {
	var user = new(User)
	user.Name = userRec.Name
	user.pass = userRec.Pass
	user.State = userRec.State
	user.MaxEnrollments = userRec.MaxEnrollments
	user.Affiliation = userRec.Affiliation
	user.Type = userRec.Type
	user.Level = userRec.Level
	user.IncorrectPasswordAttempts = userRec.IncorrectPasswordAttempts

	var attrs []api.Attribute
	json.Unmarshal([]byte(userRec.Attributes), &attrs)
	user.Attributes = attrs

	user.attrs = make(map[string]api.Attribute)
	for _, attr := range attrs {
		user.attrs[attr.Name] = api.Attribute{
			Name:  attr.Name,
			Value: attr.Value,
			ECert: attr.ECert,
		}
	}

	user.db = db
	return user
}

// GetName returns the enrollment ID of the user
func (u *User) GetName() string {
	return u.Name
}

// GetPass returns the hashed password of the user
func (u *User) GetPass() []byte {
	return u.pass
}

// GetType returns the type of the user
func (u *User) GetType() string {
	return u.Type
}

// GetMaxEnrollments returns the max enrollments of the user
func (u *User) GetMaxEnrollments() int {
	return u.MaxEnrollments
}

// GetLevel returns the level of the user
func (u *User) GetLevel() int {
	return u.Level
}

// SetLevel sets the level of the user
func (u *User) SetLevel(level int) error {
	return u.setLevel(nil, level)
}

// SetLevelTx sets the level of the user
func (u *User) SetLevelTx(tx FabricCATx, level int) error {
	return u.setLevel(tx, level)
}

func (u *User) setLevel(tx FabricCATx, level int) (err error) {
	query := "UPDATE users SET level = ? where (id = ?)"
	id := u.GetName()
	var res sql.Result
	if tx != nil {
		res, err = tx.Exec(tx.Rebind(query), level, id)
		if err != nil {
			return err
		}
	} else {
		res, err = u.db.Exec(u.db.Rebind(query), level, id)
		if err != nil {
			return err
		}
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "Failed to get number of rows affected")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", id)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, id)
	}
	return nil
}

// Login the user with a password
func (u *User) Login(pass string, caMaxEnrollments int) error {
	log.Debugf("DB: Login user %s with max enrollments of %d and state of %d", u.Name, u.MaxEnrollments, u.State)

	// Check the password by comparing to stored hash
	err := bcrypt.CompareHashAndPassword(u.pass, []byte(pass))
	if err != nil {
		err2 := u.IncrementIncorrectPasswordAttempts()
		if err2 != nil {
			return errors.Wrap(err2, "Failed to mark incorrect password attempt")
		}
		return errors.Wrap(err, "Password mismatch")
	}

	if u.MaxEnrollments == 0 {
		return errors.Errorf("Zero is an invalid value for maximum enrollments on identity '%s'", u.Name)
	}

	if u.State == -1 {
		return errors.Errorf("User %s is revoked; access denied", u.Name)
	}

	// If max enrollment value of user is greater than allowed by CA, using CA max enrollment value for user
	if caMaxEnrollments != -1 && (u.MaxEnrollments > caMaxEnrollments || u.MaxEnrollments == -1) {
		log.Debugf("Max enrollment value (%d) of identity is greater than allowed by CA, using CA max enrollment value of %d", u.MaxEnrollments, caMaxEnrollments)
		u.MaxEnrollments = caMaxEnrollments
	}

	// If maxEnrollments is set to -1, user has unlimited enrollment
	// If the maxEnrollments is set (i.e. >= 1), make sure we haven't exceeded this number of logins.
	// The state variable keeps track of the number of previously successful logins.
	if u.MaxEnrollments != -1 && u.State >= u.MaxEnrollments {
		return errors.Errorf("The identity %s has already enrolled %d times, it has reached its maximum enrollment allowance", u.Name, u.MaxEnrollments)
	}

	log.Debugf("DB: identity %s successfully logged in", u.Name)

	return u.resetIncorrectLoginAttempts()
}

func (u *User) resetIncorrectLoginAttempts() error {
	var passAttempts int
	err := u.db.Get(&passAttempts, u.db.Rebind("Select incorrect_password_attempts FROM users WHERE (id = ?)"), u.GetName())
	if err != nil {
		return errors.Wrapf(err, "Failed to get incorrect password attempt for %s", u.Name)
	}

	// Incorrect password attempts already at zero, don't need to reset
	if passAttempts == 0 {
		return nil
	}

	resetSQL := "UPDATE users SET incorrect_password_attempts = 0 WHERE (id = ?)"
	res, err := u.db.Exec(u.db.Rebind(resetSQL), u.GetName())
	if err != nil {
		return errors.Wrapf(err, "Failed to update incorrect password attempt count to 0 for %s", u.Name)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "db.RowsAffected failed")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", u.Name)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, u.Name)
	}

	return nil
}

// LoginComplete completes the login process by incrementing the state of the user
func (u *User) LoginComplete() error {
	var stateUpdateSQL string
	var args []interface{}
	var err error

	state := u.State + 1
	args = append(args, u.Name)
	if u.MaxEnrollments == -1 {
		// unlimited so no state check
		stateUpdateSQL = "UPDATE users SET state = state + 1 WHERE (id = ?)"
	} else {
		// state must be less than max enrollments
		stateUpdateSQL = "UPDATE users SET state = state + 1 WHERE (id = ? AND state < ?)"
		args = append(args, u.MaxEnrollments)
	}
	res, err := u.db.Exec(u.db.Rebind(stateUpdateSQL), args...)
	if err != nil {
		return errors.Wrapf(err, "Failed to update state of identity %s to %d", u.Name, state)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "db.RowsAffected failed")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", u.Name)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, u.Name)
	}

	log.Debugf("Successfully incremented state for identity %s to %d", u.Name, state)
	return nil

}

// GetAffiliationPath returns the complete path for the user's affiliation.
func (u *User) GetAffiliationPath() []string {
	affiliationPath := strings.Split(u.Affiliation, ".")
	return affiliationPath
}

// GetAttribute returns the value for an attribute name
func (u *User) GetAttribute(name string) (*api.Attribute, error) {
	value, hasAttr := u.attrs[name]
	if !hasAttr {
		return nil, errors.Errorf("User does not have attribute '%s'", name)
	}
	return &value, nil
}

// GetAttributes returns the requested attributes. Return all the user's
// attributes if nil is passed in
func (u *User) GetAttributes(attrNames []string) ([]api.Attribute, error) {
	var attrs []api.Attribute
	if attrNames == nil {
		for _, value := range u.attrs {
			attrs = append(attrs, value)
		}
		return attrs, nil
	}

	for _, name := range attrNames {
		value, hasAttr := u.attrs[name]
		if !hasAttr {
			return nil, errors.Errorf("User does not have attribute '%s'", name)
		}
		attrs = append(attrs, value)
	}
	return attrs, nil
}

// Revoke will revoke the user, setting the state of the user to be -1
func (u *User) Revoke() error {
	stateUpdateSQL := "UPDATE users SET state = -1 WHERE (id = ?)"

	res, err := u.db.Exec(u.db.Rebind(stateUpdateSQL), u.GetName())
	if err != nil {
		return errors.Wrapf(err, "Failed to update state of identity %s to -1", u.Name)
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "db.RowsAffected failed")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", u.Name)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, u.Name)
	}

	log.Debugf("Successfully incremented state for identity %s to -1", u.Name)

	return nil
}

// IsRevoked returns back true if user is revoked
func (u *User) IsRevoked() bool {
	if u.State == -1 {
		return true
	}
	return false
}

// ModifyAttributesTx adds a new attribute, modifies existing attribute, or delete attribute
func (u *User) ModifyAttributesTx(tx FabricCATx, newAttrs []api.Attribute) error {
	return u.modifyAttributes(tx, newAttrs)
}

// ModifyAttributes adds a new attribute, modifies existing attribute, or delete attribute
func (u *User) ModifyAttributes(newAttrs []api.Attribute) error {
	return u.modifyAttributes(nil, newAttrs)
}

func (u *User) modifyAttributes(tx FabricCATx, newAttrs []api.Attribute) error {
	log.Debugf("Modify Attributes: %+v", newAttrs)
	currentAttrs, _ := u.GetAttributes(nil)
	userAttrs := GetNewAttributes(currentAttrs, newAttrs)

	attrBytes, err := json.Marshal(userAttrs)
	if err != nil {
		return err
	}

	query := "UPDATE users SET attributes = ? WHERE (id = ?)"
	id := u.GetName()
	var res sql.Result
	if tx == nil {
		res, err = u.db.Exec(u.db.Rebind(query), string(attrBytes), id)
		if err != nil {
			return err
		}
	} else {
		res, err = tx.Exec(tx.Rebind(query), string(attrBytes), id)
		if err != nil {
			return err
		}
	}

	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "Failed to get number of rows affected")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", id)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, id)
	}
	return nil
}

// GetNewAttributes updates existing attribute, or add attribute if it does not already exist
func GetNewAttributes(modifyAttrs, newAttrs []api.Attribute) []api.Attribute {
	var attr api.Attribute
	for _, attr = range newAttrs {
		log.Debugf("Attribute request: %+v", attr)
		found := false
		for i := range modifyAttrs {
			if modifyAttrs[i].Name == attr.Name {
				if attr.Value == "" {
					log.Debugf("Deleting attribute: %+v", modifyAttrs[i])
					if i == len(modifyAttrs)-1 {
						modifyAttrs = modifyAttrs[:len(modifyAttrs)-1]
					} else {
						modifyAttrs = append(modifyAttrs[:i], modifyAttrs[i+1:]...)
					}
				} else {
					log.Debugf("Updating existing attribute from '%+v' to '%+v'", modifyAttrs[i], attr)
					modifyAttrs[i].Value = attr.Value
					modifyAttrs[i].ECert = attr.ECert
				}
				found = true
				break
			}
		}
		if !found && attr.Value != "" {
			log.Debugf("Adding '%+v' as new attribute", attr)
			modifyAttrs = append(modifyAttrs, attr)
		}
	}
	return modifyAttrs
}

// IncrementIncorrectPasswordAttempts updates the incorrect password count of user
func (u *User) IncrementIncorrectPasswordAttempts() error {
	log.Debugf("Incorrect password entered by user '%s'", u.GetName())
	query := "UPDATE users SET incorrect_password_attempts = incorrect_password_attempts + 1 where (id = ?)"
	id := u.GetName()
	res, err := u.db.Exec(u.db.Rebind(query), id)
	if err != nil {
		return err
	}
	numRowsAffected, err := res.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "Failed to get number of rows affected")
	}

	if numRowsAffected == 0 {
		return errors.Errorf("No rows were affected when updating the state of identity %s", id)
	}

	if numRowsAffected != 1 {
		return errors.Errorf("%d rows were affected when updating the state of identity %s", numRowsAffected, id)
	}
	return nil
}

// GetFailedLoginAttempts returns the number of times the user has entered an incorrect password
func (u *User) GetFailedLoginAttempts() int {
	return u.IncorrectPasswordAttempts
}
