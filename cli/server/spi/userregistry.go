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

/*
 * This file contains interfaces for the COP library.
 * COP provides police-like security functions for Hyperledger Fabric.
 */

package spi

import "github.com/hyperledger/fabric-cop/idp"

// UserInfo contains information about a user
type UserInfo struct {
	Name       string
	Pass       string
	Type       string
	Group      string
	Attributes []idp.Attribute
}

// GroupInfo defines a group name and its parent
type GroupInfo struct {
	Name     string `db:"name"`
	ParentID string `db:"parent_id"`
}

// User is the SPI for a user
type User interface {
	// Returns the enrollment ID of the user
	GetName() string
	// Login the user with a password
	Login(password string) error
	// Get the complete path for the user's affiliation.
	GetAffiliationPath() []string
	// GetAttribute returns the value for an attribute name
	GetAttribute(name string) string
}

// Group is the API for a group
type Group interface {
	GetName() string
	GetParent() string
	GetChildren() ([]Group, error)
}

// UserRegistry is the API for retreiving users and groups
type UserRegistry interface {
	GetUser(id string, attrs ...string) (User, error)
	InsertUser(user UserInfo) error
	UpdateUser(user UserInfo) error
	DeleteUser(id string) error
	UpdateField(id string, field int, value interface{}) error
	GetField(id string, field int) (interface{}, error)
	GetGroup(name string) (Group, error)
	GetRootGroup() (Group, error)
	InsertGroup(name string, parentID string) error
	DeleteGroup(name string) error
}
