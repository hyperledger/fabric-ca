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
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	_ "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/log"

	cop "github.com/hyperledger/fabric-cop/api"
	lib "github.com/hyperledger/fabric-cop/lib/defaultImpl"
)

// registerHandler for register requests
type registerHandler struct {
}

type Attribute struct {
	Name  string   `json:"name"`
	Value []string `json:"value"`
}

// var db = SQLiteDB(ecaDB)
// var dbAccessor = sql.NewAccessor(db)

// NewRegisterHandler is constructor for register handler
func NewRegisterHandler() (h http.Handler, err error) {
	// NewHandler is constructor for register handler
	return &api.HTTPHandler{
		Handler: &registerHandler{},
		Methods: []string{"POST"},
	}, nil
}

// Handle a register request
func (h *registerHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("register request received")

	reg := lib.NewRegisterUser()
	// cfg := config.CFG
	//
	// reg.DB, _ = util.GetDB(cfg.DBdriver, cfg.DataSource)
	//
	// reg.DbAccessor = lib.NewAccessor(reg.DB)

	// Read request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Parse request body
	var reqBody cop.RegisterRequest
	err = json.Unmarshal(body, &reqBody)
	if err != nil {
		return err
	}

	log.Debug("reqBody: ", reqBody)
	// // TODO: Parse the token from the Authorization header and ensure
	// //       the caller has registrar authority.  Then register appropriately.

	attributes, _ := json.Marshal(reqBody.Attributes)

	// Register User
	tok, _ := reg.RegisterUser(reqBody.User, reqBody.Group, string(attributes), reqBody.CallerID)

	log.Debug("wrote response")
	return api.SendResponse(w, []byte(tok))
}
