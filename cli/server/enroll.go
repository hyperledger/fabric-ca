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
	"fmt"
	"io/ioutil"
	"net/http"

	cfsslapi "github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/hyperledger/fabric-cop/util"
)

// NewEnrollHandler is the constructor for the enroll handler
func NewEnrollHandler() (h http.Handler, err error) {
	return newSignHandler("enroll")
}

// NewReenrollHandler is the constructor for the reenroll handler
func NewReenrollHandler() (h http.Handler, err error) {
	return newSignHandler("reenroll")
}

// signHandler for enroll or reenroll requests
type signHandler struct {
	// "enroll" or "reenroll"
	endpoint string
}

// newEnrollHandler is the constructor for an enroll or reenroll handler
func newSignHandler(endpoint string) (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &cfsslapi.HTTPHandler{
		Handler: &signHandler{endpoint: endpoint},
		Methods: []string{"POST"},
	}, nil
}

// Handle an enroll or reenroll request.
// Authentication has already occurred for both enroll and reenroll prior
// to calling this function in auth.go.
func (sh *signHandler) Handle(w http.ResponseWriter, r *http.Request) error {

	log.Debugf("Received request for endpoint %s", sh.endpoint)

	// Read the request's body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Unmarshall the request body
	var req signer.SignRequest
	err = util.Unmarshal(body, &req, sh.endpoint)
	if err != nil {
		return err
	}

	cert, err := enrollSigner.Sign(req)
	if err != nil {
		err = fmt.Errorf("Failed signing for endpoint %s: %s", sh.endpoint, err)
		log.Error(err.Error())
		return err
	}

	return cfsslapi.SendResponse(w, cert)
}
