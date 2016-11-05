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

package tcert

import (
	"encoding/json"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Handler for tcert requests
type Handler struct {
}

// NewTcertHandler is constructor for tcert handler
func NewTcertHandler() (h http.Handler, err error) {
	return &api.HTTPHandler{
		Handler: &Handler{},
		Methods: []string{"POST"},
	}, nil
}

// Handle a tcert request
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	body, _ := ioutil.ReadAll(r.Body)
	Values, _ := url.ParseQuery(string(body))

	var output map[string]interface{}

	//Tcertjson := Values["Tcertjson"]
	signaturejson := Values["signature"]

	var sigmap map[string]string
	//var ecertstring string
	//var tcertjson string

	//tcertjson := Tcertjson[0]

	for _, s := range signaturejson {
		if strings.Contains(s, "Certificate") {
			json.Unmarshal([]byte(s), &sigmap)
			//ecertstring := sigmap["Certificate"]
		}
	}
	//TODO: need to verify request
	//TODO: need to create tcert and return tcert to client
	//isVerfiied := utils.VerifyMessage(tcertjson, signaturejson[0])

	r.Body.Close()

	json.Unmarshal([]byte(string(body)), &output)

	log.Debug("wrote response")
	//result from COP server
	result := output

	return api.SendResponse(w, result)
}
