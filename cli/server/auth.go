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

package server

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	cerr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/hyperledger/fabric-cop/util"
)

const (
	enrollmentIDHdrName = "__eid__"
)

// AuthHandler
type copAuthHandler struct {
	basic bool
	token bool
	next  http.Handler
}

var authError = cerr.NewBadRequest(errors.New("authorization failure"))

// NewAuthWrapper is auth wrapper constructor
// Only the "sign" and "enroll" URIs use basic auth for the enrollment secret
// The others require a token
func NewAuthWrapper(path string, handler http.Handler, err error) (string, http.Handler, error) {
	if path == "sign" || path == "enroll" {
		handler, err = newBasicAuthHandler(handler, err)
		return wrappedPath(path), handler, err
	}
	handler, err = newTokenAuthHandler(handler, err)
	return wrappedPath(path), handler, err
}

func newBasicAuthHandler(handler http.Handler, errArg error) (h http.Handler, err error) {
	return newAuthHandler(true, false, handler, errArg)
}

func newTokenAuthHandler(handler http.Handler, errArg error) (h http.Handler, err error) {
	return newAuthHandler(false, true, handler, errArg)
}

func newAuthHandler(basic, token bool, handler http.Handler, errArg error) (h http.Handler, err error) {
	log.Debug("newAuthHandler")
	if errArg != nil {
		return nil, errArg
	}
	ah := new(copAuthHandler)
	ah.basic = basic
	ah.token = token
	ah.next = handler
	return ah, nil
}

func (ah *copAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := ah.serveHTTP(w, r)
	if err != nil {
		api.HandleError(w, err)
	} else {
		ah.next.ServeHTTP(w, r)
	}
}

// Handle performs authentication
func (ah *copAuthHandler) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	log.Infof("Received request\n%s", util.HTTPRequestToString(r))
	cfg := CFG
	if !cfg.Authentication {
		log.Debug("Authentication is disabled")
		return nil
	}
	authHdr := r.Header.Get("authorization")
	if authHdr == "" {
		log.Debug("No authorization header")
		return errNoAuthHdr
	}
	user, pwd, ok := r.BasicAuth()
	if ok {
		if !ah.basic {
			log.Debugf("Basic auth is not allowed; found %s", authHdr)
			return errBasicAuthNotAllowed
		}
		u, err := userRegistry.GetUser(user, nil)
		if err != nil {
			return err
		}
		err = u.Login(pwd)
		if err != nil {
			return err
		}
		log.Debug("User/Pass was correct")
		r.Header.Set(enrollmentIDHdrName, user)
		// TODO: Do the following
		// 2) Update state of 'user' in DB as enrolled and return true.
		return nil
	}
	// Perform token verification
	if ah.token {
		// read body
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return authError
		}
		r.Body = ioutil.NopCloser(bytes.NewReader(body))
		// verify token
		cert, err2 := util.VerifyToken(authHdr, body)
		if err2 != nil {
			return authError
		}
		// Check for certificate revocation and expiration
		revokedOrExpired, checked := revoke.VerifyCertificate(cert)
		if revokedOrExpired {
			log.Debug("Certificate was either revoked or has expired")
			return authError
		}
		if !checked {
			log.Debug("A failure occurred while checking for revocation and expiration")
			return authError
		}
		r.Header.Set(enrollmentIDHdrName, util.GetEnrollmentIDFromX509Certificate(cert))
	}
	return nil
}

func wrappedPath(path string) string {
	return "/api/v1/cfssl/" + path
}
