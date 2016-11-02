package server

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
)

// registerHandler for register requests
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

// Handle a register request
func (h *enrollHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Debug("enroll request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()
	//
	var request cop.EnrollRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		return err
	}

	//enroll := NewEnrollUser()
	//cert, _ := enroll.Enroll(request.User, request.Token, request.CSR, r.Host)

	return api.SendResponse(w, "bogus")
}
