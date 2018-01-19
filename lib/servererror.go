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

package lib

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	cfsslapi "github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
)

// Error codes
const (
	// Unknown error code
	ErrUnknown = 0
	// HTTP method not allowed
	ErrMethodNotAllowed = 1
	// No authorization header was found in request
	ErrNoAuthHdr = 2
	// Failed reading the HTTP request body
	ErrReadingReqBody = 3
	// HTTP request body was empty but should not have been
	ErrEmptyReqBody = 4
	// HTTP request body was of the wrong format
	ErrBadReqBody = 5
	// The token in the authorization header was invalid
	ErrBadReqToken = 6
	// The caller does not have the "hf.Revoker" attibute
	ErrNotRevoker = 7
	// Certificate to be revoked was not found
	ErrRevCertNotFound = 8
	// Certificate to be revoked is not owned by expected user
	ErrCertWrongOwner = 9
	// Identity of certificate to be revoked was not found
	ErrRevokeIDNotFound = 10
	// User info was not found for issuee of revoked certificate
	ErrRevokeUserInfoNotFound = 11
	// Certificate revocation failed for another reason
	ErrRevokeFailure = 12
	// Failed to update user info when revoking identity
	ErrRevokeUpdateUser = 13
	// Failed to revoke any certificates by identity
	ErrNoCertsRevoked = 14
	// Missing fields in the revocation request
	ErrMissingRevokeArgs = 15
	// Failed to get user's affiliation
	ErrGettingAffiliation = 16
	// Revoker's affiliation not equal to or above revokee's affiliation
	ErrRevokerNotAffiliated = 17
	// Failed to send an HTTP response
	ErrSendingResponse = 18
	// The CA (Certificate Authority) name was not found
	ErrCANotFound = 19
	// Authorization failure
	ErrAuthFailure = 20
	// No username and password were in the authorization header
	ErrNoUserPass = 21
	// Enrollment is currently disabled for the server
	ErrEnrollDisabled = 22
	// Invalid user name
	ErrInvalidUser = 23
	// Invalid password
	ErrInvalidPass = 24
	// Invalid token in authorization header
	ErrInvalidToken = 25
	// Certificate was not issued by a trusted authority
	ErrUntrustedCertificate = 26
	// Certificate has expired
	ErrCertExpired = 27
	// Certificate has been revoked
	ErrCertRevoked = 28
	// Failed trying to check if certificate is revoked
	ErrCertRevokeCheckFailure = 29
	// Certificate was not found
	ErrCertNotFound = 30
	// Bad certificate signing request
	ErrBadCSR = 31
	// Failed to get identity's prekey
	ErrNoPreKey = 32
	// The caller was not authenticated
	ErrCallerIsNotAuthenticated = 33
	// Invalid configuration setting
	ErrConfig = 34
	// The caller does not have authority to generate a CRL
	ErrNoGenCRLAuth = 35
	// Invalid RevokedAfter value in the GenCRL request
	ErrInvalidRevokedAfter = 36
	// Invalid ExpiredAfter value in the GenCRL request
	ErrInvalidExpiredAfter = 37
	// Failed to get revoked certs from the database
	ErrRevokedCertsFromDB = 38
	// Failed to get CA cert
	ErrGetCACert = 39
	// Failed to get CA signer
	ErrGetCASigner = 40
	// Failed to generate CRL
	ErrGenCRL = 41
	// Registrar does not have the authority to register an attribute
	ErrRegAttrAuth = 42
	// Registrar does not own 'hf.Registrar.Attributes'
	ErrMissingRegAttr = 43
	// Caller does not have appropriate affiliation to perform requested action
	ErrCallerNotAffiliated = 44
	// Failed to verify if caller has appropriate type
	ErrGettingType = 45
	// CA cert does not have 'crl sign' usage
	ErrNoCrlSignAuth = 46
	// Incorrect level of database
	ErrDBLevel = 47
	// Incorrect level of configuration file
	ErrConfigFileLevel = 48
	// Failed to get user from database
	ErrGettingUser = 49
	// Error processing HTTP request
	ErrHTTPRequest = 50
	// Error connecting to database
	ErrConnectingDB = 51
	// Failed to add identity
	ErrAddIdentity = 52
	// Unauthorized to perform update action
	ErrUpdateConfigAuth = 53
	// Registrar not authorized to act on type
	ErrRegistrarInvalidType = 54
	// Registrar not authorized to act on affiliation
	ErrRegistrarNotAffiliated = 55
	// Failed to remove identity
	ErrRemoveIdentity = 56
	// Failed to get boolean query parameter
	ErrGettingBoolQueryParm = 57
	// Failed to modify identity
	ErrModifyingIdentity = 58
	// Caller does not have the appropriate role
	ErrMissingRole = 59
	// Failed to add new affiliation
	ErrUpdateConfigAddAff = 60
	// Failed to remove affiliation
	ErrUpdateConfigRemoveAff = 61
	// Error occured while removing affiliation in database
	ErrRemoveAffDB = 62
	// Error occured when making a Get request to database
	ErrDBGet = 63
	// Failed to modiy affiliation
	ErrUpdateConfigModifyAff = 64
	// Error occured while deleting user
	ErrDBDeleteUser = 65
	// Certificate that is being revoked has already been revoked
	ErrCertAlreadyRevoked = 66
)

// Construct a new HTTP error.
func createHTTPErr(scode, code int, format string, args ...interface{}) *httpErr {
	msg := fmt.Sprintf(format, args...)
	return &httpErr{
		scode: scode,
		lcode: code,
		lmsg:  msg,
		rcode: code,
		rmsg:  msg,
	}
}

// Construct a new HTTP error wrappered with pkg/errors error.
func newHTTPErr(scode, code int, format string, args ...interface{}) error {
	return errors.Wrap(createHTTPErr(scode, code, format, args...), "")
}

// Construct an HTTP error specifically indicating an authorization failure.
// The local code and message is specific, but the remote code and message is generic
// for security reasons.
func newAuthErr(code int, format string, args ...interface{}) error {
	he := createHTTPErr(401, code, format, args...)
	he.Remote(ErrAuthFailure, "Authorization failure")
	return errors.Wrap(he, "")
}

// httpErr is an HTTP error.
// "local" refers to errors as logged in the server (local to the server).
// "remote" refers to errors as returned to the client (remote to the server).
// This allows us to log a more specific error in the server logs while
// returning a more generic error to the client, as is done for authorization
// failures.
type httpErr struct {
	scode int    // HTTP status code
	lcode int    // local error code
	lmsg  string // local error message
	rcode int    // remote error code
	rmsg  string // remote error message
}

// Error returns the string representation
func (he *httpErr) Error() string {
	return he.String()
}

// String returns a string representation of this augmented error
func (he *httpErr) String() string {
	if he.lcode == he.rcode && he.lmsg == he.rmsg {
		return fmt.Sprintf("scode: %d, code: %d, msg: %s", he.scode, he.lcode, he.lmsg)
	}
	return fmt.Sprintf("scode: %d, local code: %d, local msg: %s, remote code: %d, remote msg: %s",
		he.scode, he.lcode, he.lmsg, he.rcode, he.rmsg)
}

// Set the remote code and message to something different from that of the local code and message
func (he *httpErr) Remote(code int, format string, args ...interface{}) *httpErr {
	he.rcode = code
	he.rmsg = fmt.Sprintf(format, args...)
	return he
}

// Write the server's HTTP error response
func (he *httpErr) writeResponse(w http.ResponseWriter) error {
	response := cfsslapi.NewErrorResponse(he.rmsg, he.rcode)
	jsonMessage, err := json.Marshal(response)
	if err != nil {
		log.Errorf("Failed to marshal error to JSON: %v", err)
		return err
	}
	msg := string(jsonMessage)
	http.Error(w, msg, he.scode)
	return nil
}

type fatalErr struct {
	code int
	msg  string
}

func newFatalError(code int, format string, args ...interface{}) *fatalErr {
	msg := fmt.Sprintf(format, args...)
	return &fatalErr{
		code: code,
		msg:  msg,
	}
}

func (fe *fatalErr) Error() string {
	return fe.String()
}

func (fe *fatalErr) String() string {
	return fmt.Sprintf("Code: %d - %s", fe.code, fe.msg)
}

func isFatalError(err error) bool {
	causeErr := errors.Cause(err)
	typ := reflect.TypeOf(causeErr)
	// If a pointer to a struct is passe, get the type of the dereferenced object
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if typ == reflect.TypeOf(fatalErr{}) {
		return true
	}
	return false
}
