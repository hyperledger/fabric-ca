/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cfssl/api"
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
	testEndpoint(t, "DELETE", url, 405, ErrMethodNotAllowed)
	handlerError = newAuthErr(ErrInvalidToken, "Invalid token")
	testEndpoint(t, "GET", url, 401, ErrAuthFailure)
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

func testEndpointHandler(ctx *serverRequestContext) (interface{}, error) {
	return "result", handlerError
}
