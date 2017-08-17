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
	if err == nil {
		resp, err = se.Handler(newServerRequestContext(r, w, se))
	}
	if r.Method == "HEAD" {
		w.Header().Set("Content-Length", "0")
		he := getHTTPErr(err)
		if he != nil {
			w.WriteHeader(he.scode)
			log.Infof(`%s %s %s %d %d "%s"`, r.RemoteAddr, r.Method, r.URL, he.scode, he.lcode, he.lmsg)
		} else {
			w.WriteHeader(200)
			log.Infof(`%s %s %s 200 0 "OK"`, r.RemoteAddr, r.Method, r.URL)
		}
	} else if err == nil {
		w.WriteHeader(200)
		err = api.SendResponse(w, resp)
		if err != nil {
			log.Warning("Failed to send response for %s: %+v", url, err)
		} else {
			log.Debugf("Sent response for %s: %+v", url, resp)
		}
		log.Infof(`%s %s %s 200 0 "OK"`, r.RemoteAddr, r.Method, r.URL)
	} else {
		he := getHTTPErr(err)
		he.writeResponse(w)
		log.Debugf("Sent error for %s: %+v", url, err)
		log.Infof(`%s %s %s %d %d "%s"`, r.RemoteAddr, r.Method, r.URL, he.scode, he.lcode, he.lmsg)
	}
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

// Get the top-most HTTP error from the cause stack.
// If not found, create one with an unknown error code.
func getHTTPErr(err error) *httpErr {
	if err == nil {
		return nil
	}
	type causer interface {
		Cause() error
	}
	curErr := err
	for curErr != nil {
		switch curErr.(type) {
		case *httpErr:
			return curErr.(*httpErr)
		case causer:
			curErr = curErr.(causer).Cause()
		default:
			return createHTTPErr(500, ErrUnknown, err.Error())
		}
	}
	return createHTTPErr(500, ErrUnknown, "nil error")
}
