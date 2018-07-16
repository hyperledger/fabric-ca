/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package caerrors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorString(t *testing.T) {
	msg := "message"
	err := NewHTTPErr(400, ErrMethodNotAllowed, "%s", msg)
	errMsg := err.Error()
	assert.Contains(t, errMsg, msg)
}

func TestHTTPErr(t *testing.T) {
	msg := "message"
	err := CreateHTTPErr(400, ErrMethodNotAllowed, "%s", msg)
	errMsg := err.Error()
	assert.Contains(t, errMsg, msg)
	assert.Equal(t, err.GetRemoteCode(), ErrMethodNotAllowed)
	assert.Equal(t, err.GetLocalCode(), ErrMethodNotAllowed)
	assert.Equal(t, err.GetRemoteMsg(), "message")
	assert.Equal(t, err.GetStatusCode(), 400)
	assert.Equal(t, err.GetLocalMsg(), "message")

	w := &mockHTTPWriter{httptest.NewRecorder()}
	assert.NoError(t, err.writeResponse(w))
}

func TestRemoteErrorString(t *testing.T) {
	lmsg := "local message"
	rmsg := "remote message"
	err := CreateHTTPErr(401, ErrMethodNotAllowed, "%s", lmsg).Remote(ErrUnknown, rmsg)
	errMsg := err.Error()
	assert.Contains(t, errMsg, rmsg)
}

func TestNewAuthenticationError(t *testing.T) {
	lmsg := "local message"
	err := NewAuthenticationErr(ErrAuthenticationFailure, "%s", lmsg)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "Authentication failure")
}

func TestNewAuthorizationError(t *testing.T) {
	lmsg := "local message"
	err := NewAuthorizationErr(ErrAuthorizationFailure, "%s", lmsg)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "Authorization failure")
}

func TestServerError(t *testing.T) {
	err := NewServerError(24, "error: %s", "server")
	assert.Equal(t, err.code, 24)
	assert.Equal(t, err.msg, "error: server")
}

func TestFatalError(t *testing.T) {
	err := NewFatalError(25, "fatal error: %s", "server")
	assert.Equal(t, err.code, 25)
	assert.Equal(t, err.msg, "fatal error: server")

	assert.Equal(t, err.Error(), "Code: 25 - fatal error: server")
}

func TestIsFatalError(t *testing.T) {
	ferr := NewFatalError(25, "fatal error: %s", "server")
	assert.Equal(t, IsFatalError(ferr), true)

	err := NewAuthorizationErr(25, "%s", "auth error")
	assert.Equal(t, IsFatalError(err), false)
}

type mockHTTPWriter struct {
	http.ResponseWriter
}

// Header returns the header map that will be sent by WriteHeader.
func (m *mockHTTPWriter) Header() http.Header {
	return m.ResponseWriter.Header()
}

// Write writes the data to the connection as part of an HTTP reply.
func (m *mockHTTPWriter) Write(buf []byte) (int, error) {
	w := m.ResponseWriter
	return w.Write(buf)
}
