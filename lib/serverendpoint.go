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
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
)

// serverEndpoint represents a particular endpoint (e.g. to "/api/v1/enroll")
type serverEndpoint struct {
	// The HTTP methods ("GET", "POST", etc) which the function will handle
	Methods []string
	// Handler is the handler function for this endpoint
	Handler func(ctx *serverRequestContext) (interface{}, error)
	// Server which hosts this endpoint
	Server *Server
}

// ServeHTTP encapsulates the call to underlying Handlers to handle the request
// and return the response with a proper HTTP status code
func (se *serverEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	url := r.URL.String()
	log.Debugf("Received request for %s", url)
	err := se.validateMethod(r)
	var resp interface{}
	if err == nil && r.Method != "HEAD" {
		resp, err = se.Handler(newServerRequestContext(r, w, se))
	}
	var scode, lcode int
	if err == nil {
		// No error
		scode = 200
		lcode = 0
		w.WriteHeader(scode)
		api.SendResponse(w, resp)
		log.Debugf("Sent response for %s: %+v", url, resp)
	} else {
		var he *httpErr
		switch err.(type) {
		case *httpErr:
			he = err.(*httpErr)
		default:
			he = newHTTPErr(500, ErrUnknown, err.Error())
		}
		scode = he.scode
		lcode = he.lcode
		he.writeResponse(w)
		log.Debugf("Sent error for %s: %+v", url, he)
	}
	// Create access log entry
	log.Infof("%s - \"%s %s\" %d %d", r.RemoteAddr, r.Method, r.URL, scode, lcode)
}

// Validate that the HTTP method is supported for this endpoint
func (se *serverEndpoint) validateMethod(r *http.Request) error {
	for _, m := range se.Methods {
		if m == r.Method {
			return nil
		}
	}
	return newHTTPErr(405, ErrMethodNotAllowed, "Method %s is not allowed", r.Method)
}
