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
