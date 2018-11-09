/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
 * This file defines the user registry interface used by the fabric-ca server.
 */

package spi

import (
	"github.com/hyperledger/fabric-ca/api"
	"github.com/jmoiron/sqlx"
)

// UserInfo contains information about a user
type UserInfo struct {
	Name                      string
	Pass                      string `mask:"password"`
	Type                      string
	Affiliation               string
	Attributes                []api.Attribute
	State                     int
	MaxEnrollments            int
	Level                     int
	IncorrectPasswordAttempts int
}

// DbTxResult returns information on any affiliations and/or identities affected
// during a database transaction
type DbTxResult struct {
	Affiliations []Affiliation
	Identities   []User
}

// User is the SPI for a user
type User interface {
	// Returns the enrollment ID of the user
	GetName() string
	// Return the type of the user
	GetType() string
	// Return the max enrollments of the user
	GetMaxEnrollments() int
	// Login the user with a password
	Login(password string, caMaxEnrollment int) error
	// Get the complete path for the user's affiliation.
	GetAffiliationPath() []string
	// GetAttribute returns the value for an attribute name
	GetAttribute(name string) (*api.Attribute, error)
	// GetAttributes returns the requested attributes
	GetAttributes(attrNames []string) ([]api.Attribute, error)
	// ModifyAttributes adds, removes, or deletes attribute
	ModifyAttributes(attrs []api.Attribute) error
	// LoginComplete completes the login process by incrementing the state of the user
	LoginComplete() error
	// Revoke will revoke the user, setting the state of the user to be -1
	Revoke() error
	// IsRevoked returns back true if user is revoked
	IsRevoked() bool
	// GetLevel returns the level of the user, level is used to verify if the user needs migration
	GetLevel() int
	// SetLevel sets the level of the user
	SetLevel(level int) error
	// IncrementIncorrectPasswordAttempts updates the incorrect password count of user
	IncrementIncorrectPasswordAttempts() error
	// GetFailedLoginAttempts returns the number of times the user has entered an incorrect password
	GetFailedLoginAttempts() int
}

// UserRegistry is the API for retreiving users and groups
type UserRegistry interface {
	GetUser(id string, attrs []string) (User, error)
	InsertUser(user *UserInfo) error
	UpdateUser(user *UserInfo, updatePass bool) error
	DeleteUser(id string) (User, error)
	GetAffiliation(name string) (Affiliation, error)
	GetAllAffiliations(name string) (*sqlx.Rows, error)
	InsertAffiliation(name string, prekey string, level int) error
	GetUserLessThanLevel(version int) ([]User, error)
	GetFilteredUsers(affiliation, types string) (*sqlx.Rows, error)
	DeleteAffiliation(name string, force, identityRemoval, isRegistrar bool) (*DbTxResult, error)
	ModifyAffiliation(oldAffiliation, newAffiliation string, force, isRegistrar bool) (*DbTxResult, error)
	GetAffiliationTree(name string) (*DbTxResult, error)
}
