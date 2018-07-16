/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cfssl/api"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/stretchr/testify/assert"
)

var handlerError error

func TestServerEndpoint(t *testing.T) {
	// Positive tests
	url := "http://localhost:7054/api/v1/enroll"
	handlerError = nil
	testEndpoint(t, "HEAD", url, 200, 0)
	testEndpoint(t, "GET", url, 200, 0)
	testEndpoint(t, "POST", url, 200, 0)
	// Negative tests
	testEndpoint(t, "DELETE", url, 405, caerrors.ErrMethodNotAllowed)
	handlerError = caerrors.NewAuthenticationErr(caerrors.ErrInvalidToken, "Invalid token")
	testEndpoint(t, "GET", url, 401, caerrors.ErrAuthenticationFailure)
}

func testEndpoint(t *testing.T, method, url string, scode, rcode int) {
	se := &serverEndpoint{
		Methods: []string{"GET", "POST", "HEAD"},
		Handler: testEndpointHandler,
	}
	r, err := http.NewRequest(method, url, nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	se.ServeHTTP(w, r)
	resp := w.Result()
	assert.True(t, resp.StatusCode == scode)
	buf, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)
	if method != "HEAD" {
		var body api.Response
		err = json.Unmarshal(buf, &body)
		assert.NoError(t, err)
		if rcode == 0 {
			assert.True(t, len(body.Errors) == 0)
		} else {
			assert.True(t, body.Errors[0].Code == rcode)
		}
	} else {
		// No response body
		assert.True(t, len(buf) == 0)
	}
}

func testEndpointHandler(ctx *serverRequestContextImpl) (interface{}, error) {
	return "result", handlerError
}
