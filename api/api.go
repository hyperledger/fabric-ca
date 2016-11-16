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

package api

import (
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/jmoiron/sqlx"
)

// Mgr is the main interface to COP functionality
type Mgr interface {

	// NewCertMgr creates a COP certificate manager
	NewCertMgr() CertMgr
}

// Client is a COP client
type Client interface {
	//GetTcertBatch gets a batch of tcerts
	GetTcertBatch(jsonString string, signatureJSON string) (string, error)
	// GetHomeDir returns the home directory
	GetHomeDir() string

	// SetHomeDir sets the home directory
	SetHomeDir(dir string)

	// GetServerAddr returns the server address
	GetServerAddr() string

	// SetServerAddr sets the server address
	SetServerAddr(dir string)

	// Register a new identity
	Register(registration *RegisterRequest) ([]byte, Error)

	// Enroll a registered identity
	//	Enroll(user, pass string) (Identity, Error)
	Enroll(enroll *EnrollRequest, csrJSON string) ([]byte, Error)

	// RegisterAndEnroll registers and enrolls a new identity
	RegisterAndEnroll(registration *RegisterRequest) (Identity, Error)

	/*
		// SubmitJoinRequest submits a join request, implicitly approving by the caller
		// Returns the join request ID
		SubmitJoinRequest(participantFilePath string) (JoinRequest, Error)

		// ApproveJoinRequest approves the join request
		ApproveJoinRequest(joinRequestID string) Error

		// DenyJoinRequest denies the join request
		DenyJoinRequest(joinRequestID string) Error

		// ListJoinRequests lists the currently outstanding join requests for the blockchain network
		ListJoinRequests() ([]JoinRequest, Error)

		// ListParticipants lists the current participants in the blockchain network
		ListParticipants() ([]string, Error)

		// Set the listener to be called when a JoinRequestEvent is emitted
		SetJoinRequestListener(listener JoinRequestListener)
	*/
}

// JoinRequest is the state of a request to join the blockchain network
type JoinRequest struct {
	ID        string             // Unique ID of join request
	Info      string             // The original JSON request from the participant
	Status    JoinRequestStatus  // waiting, approved, or denied
	Responses [JRTCount][]string // participant names of approvers
}

// JoinRequestListener is a listener for join requests
type JoinRequestListener func(JoinRequest)

// JoinRequestStatus is the status of a join request
type JoinRequestStatus int

// Values denoting the possible values of the JoinRequestStatus
const (
	JRSWaiting JoinRequestStatus = iota
	JRSApproved
	JRSDenied
)

// JoinResponseType are the types of responses which can be provided to a JoinRequest
type JoinResponseType int

// Values denoting the possible values of the JoinResponseType
const (
	JRTApprove JoinResponseType = iota
	JRTDeny
	JRTAbstain
	JRTCount
)

// CertMgr is the interface for all certificate-based management
type CertMgr interface {

	// GenCert generates a certificate
	GenCert(csr string, prefix string, participantFile string) Error

	// InitSelfSign generates self-signed certs and updates the participant file
	InitSelfSign(domain string, path string) Error

	// InitLego gets certificates from Let's Encrypt and updates the participant file
	InitLego(host string) Error

	// SetECAKey sets the ECA key
	SetECAKey(key []byte) Error

	// SetTCAKey sets the TCA key
	SetTCAKey(key []byte) Error

	// Set the path for the participant file
	SetParticipantFilePath(path string) Error

	// UpdateParticipantFile
	UpdateParticipantFile() Error

	// LoadFromString
	//LoadFromString(str string) Error

	// StoreToString
	//StoreToString() string

	// NewCertHandler creates a COP certificate handler
	NewCertHandler(cert []byte) (CertHandler, Error)

	// NewKeyHandler creates a COP key handler
	NewKeyHandler(key []byte) (KeyHandler, Error)
}

// CertHandler provides functions related to a certificate
type CertHandler interface {
	// GetId returns the ID of the owner of this cert
	GetID() string
	// GetPartipantId returns the participant ID associated with this cert
	GetParticipantID() string
	// Determine if the caller has a specific role (e.g. 'orderer', 'peer', etc)
	IsType(role string) bool
	// Verify a signature against this certificate
	Verify(buf []byte, signature []byte) (bool, Error)
}

// KeyHandler provides functions related to a key
type KeyHandler interface {
	CertHandler
	// Create a signature using this key
	Sign(buf []byte) ([]byte, Error)
}

// RegisterRequest information
type RegisterRequest struct {
	User       string          `json:"user"`
	Group      string          `json:"group"`
	Type       string          `json:"type"` // Type of identity being registered (e.g. "peer, app, user")
	Attributes []idp.Attribute `json:"attrs,omitempty"`
	CallerID   string          `json:"callerID"`
}

// EnrollRequest - information need to process enrollment request to server
type EnrollRequest struct {
	User  string `json:"user"`
	Token []byte `json:"token"`
	CSR   []byte `json:"csr"`
}

// Enrollment - information need to process enrollment request to client
type Enrollment struct {
	ID           string
	EnrollSecret []byte
}

// Database api

// UserRecord used for inserting into database
type UserRecord struct {
	ID           string `db:"id"`
	EnrollmentID string `db:"enrollment_id"`
	Token        string `db:"token"`
	Type         string `db:"type"`
	Metadata     string `db:"metadata"`
	State        int    `db:"state"`
	SerialNumber string `db:"serial_number"`
}

// Accessor abstracts the CRUD of certdb objects from a DB.
type Accessor interface {
	SetDB(db *sqlx.DB)
	InsertUser(user UserRecord) error
	DeleteUser(id string) error
	UpdateUser(user UserRecord) error
	GetUser(id string) (UserRecord, error)
	InsertGroup(name string, parentID string) error
	DeleteGroup(name string) error
	GetGroup(name string) (string, string, error)
}

// Identity is any type of identity which is opaque for now
type Identity interface{}

var mgr Mgr

// SetMgr sets the COP manager
func SetMgr(m Mgr) {
	mgr = m
}

// NewCertMgr creates a COP certificate manager
func NewCertMgr() CertMgr {
	return mgr.NewCertMgr()
}
