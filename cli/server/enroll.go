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
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	cerr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	cop "github.com/hyperledger/fabric-cop/api"
)

// enrollHandler for register requests
type enrollHandler struct {
}

// NewEnrollHandler is constructor for register handler
func NewEnrollHandler() (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &api.HTTPHandler{
		Handler: &enrollHandler{},
		Methods: []string{"POST"},
	}, nil
}

// Handle a enroll request
func (h *enrollHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("enroll request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("failed to read body: %s", err)
		return cerr.NewBadRequest(errors.New("failed to read request body"))
	}
	r.Body.Close()

	user, token, ok := r.BasicAuth()
	if !ok {
		log.Error("No authorization header set")
		return cerr.NewBadRequest(errors.New("missing authorization header"))
	}

	enroll := NewEnrollUser()
	cert, err := enroll.Enroll(user, []byte(token), body)
	if err != nil {
		return cerr.NewBadRequest(err)
	}

	return api.SendResponse(w, cert)
}

// Enroll is for enrolling a user
type Enroll struct {
	cfg *Config
}

// NewEnrollUser returns an pointer to an allocated enroll struct, populated
// with the DB information (that set in the config) or nil on error.
func NewEnrollUser() *Enroll {
	e := new(Enroll)
	e.cfg = CFG
	return e
}

// Enroll will enroll an already registered user and provided an enrollment cert
func (e *Enroll) Enroll(id string, token []byte, csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("Received request to enroll user with id: %s\n", id)
	mutex.Lock()
	defer mutex.Unlock()

	cert, signErr := e.signKey(csrPEM)
	if signErr != nil {
		log.Error("Failed to sign CSR - Enroll Failed")
		return nil, signErr
	}

	return cert, nil
}

func (e *Enroll) signKey(csrPEM []byte) ([]byte, cop.Error) {
	log.Debugf("signKey")
	req := signer.SignRequest{
		// Hosts:   signer.SplitHosts(c.Hostname),
		Request: string(csrPEM),
		// Profile: c.Profile,
		// Label:   c.Label,
	}
	cert, err := CFG.Signer.Sign(req)
	if err != nil {
		log.Errorf("Sign error: %s", err)
		return nil, cop.WrapError(err, cop.CFSSL, "Failed in Sign")
	}
	log.Debug("Sign success")
	return cert, nil

}
