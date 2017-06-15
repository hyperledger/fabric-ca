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
	"encoding/json"

	cfapi "github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	"io/ioutil"
	"github.com/hyperledger/fabric-ca/api"

)

// infoHandler handles the GET /info request
type ecertHandler struct {
	server *Server
}

// newInfoHandler is the constructor for the infoHandler
func newECertHandler(server *Server) (h http.Handler, err error) {
	return &cfapi.HTTPHandler{
		Handler: &ecertHandler{server: server},
		Methods: []string{"POST"},
	}, nil
}

// The response to the GET /info request
type serverECertNet struct {
	// user id
	Name string
	// Base64 encoding of PEM-encoded certificate chain
	Certificate string
}

// Handle is the handler for the GET /info request
func (eh *ecertHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("Received request for user certificate")

	// Read the request's body
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Unmarshall the request body
	var req api.UserECertRequest
	err = json.Unmarshal(reqBody, &req)
	if err != nil {
		log.Info(reqBody)
		log.Error(err.Error())
		return err
	}

	log.Debugf("ECert request: %+v\n", req)
	log.Infof("Requested userid: %s\n", req.Name)

	pem, err := eh.getUserLastCertificate(req.Name)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	log.Infof("Cert: %s\n", pem)
	//resp := &serverECertNet{req.Name, util.B64Encode(pem)}
	resp := &serverECertNet{req.Name, pem}
	return cfapi.SendResponse(w, resp)
}

// getUserLastCertificate return a user's last certificate
func (eh *ecertHandler) getUserLastCertificate(username string) (string, error) {
	log.Debug("getUserLastCertificate user=%s", username)
	//crs []CertRecord
	crs, err := eh.server.certDBAccessor.GetLastCertificatesByID(username)
	if err != nil {
		return "", err
	}

	log.Debug("getUserLastCertificate user=%s, certificate=%", username, crs[0].CertificateRecord.PEM)
	return crs[0].CertificateRecord.PEM, nil
}
