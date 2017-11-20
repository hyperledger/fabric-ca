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
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

func newAffiliationsEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"GET", "DELETE", "PUT"},
		Handler:   affiliationsHandler,
		Server:    s,
		successRC: 200,
	}
}

func newAffiliationsStreamingEndpoint(s *Server) *serverEndpoint {
	return &serverEndpoint{
		Methods:   []string{"GET", "POST"},
		Handler:   affiliationsStreamingHandler,
		Server:    s,
		successRC: 200,
	}
}

func affiliationsHandler(ctx *serverRequestContext) (interface{}, error) {
	var err error
	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	log.Debugf("Received affiliation update request from %s", callerID)
	if err != nil {
		return nil, err
	}
	caname, err := ctx.getCAName()
	if err != nil {
		return nil, err
	}
	caller, err := ctx.GetCaller()
	if err != nil {
		return nil, err
	}
	// Process Request
	resp, err := processAffiliationRequest(ctx, caname, caller)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func affiliationsStreamingHandler(ctx *serverRequestContext) (interface{}, error) {
	var err error

	// Authenticate
	callerID, err := ctx.TokenAuthentication()
	log.Debugf("Received affiliation update request from %s", callerID)
	if err != nil {
		return nil, err
	}
	caname, err := ctx.getCAName()
	if err != nil {
		return nil, err
	}
	caller, err := ctx.GetCaller()
	if err != nil {
		return nil, err
	}
	// Process Request
	resp, err := processStreamingAffiliationRequest(ctx, caname, caller)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// processStreamingAffiliationRequest will process the configuration request
func processStreamingAffiliationRequest(ctx *serverRequestContext, caname string, caller spi.User) (interface{}, error) {
	log.Debug("Processing affiliation configuration update request")

	method := ctx.req.Method
	switch method {
	case "GET":
		return nil, processGetAllAffiliationsRequest(ctx, caller, caname)
	case "POST":
		return processAffiliationPostRequest(ctx, caname)
	default:
		return nil, errors.Errorf("Invalid request: %s", method)
	}
}

// processRequest will process the configuration request
func processAffiliationRequest(ctx *serverRequestContext, caname string, caller spi.User) (interface{}, error) {
	log.Debug("Processing affiliation configuration update request")

	method := ctx.req.Method
	switch method {
	case "GET":
		return processGetAffiliationRequest(ctx, caller, caname)
	case "DELETE":
		return processAffiliationDeleteRequest(ctx, caname)
	case "PUT":
		return processAffiliationPutRequest(ctx, caname)
	default:
		return nil, errors.Errorf("Invalid request: %s", method)
	}
}

func processGetAllAffiliationsRequest(ctx *serverRequestContext, caller spi.User, caname string) error {
	log.Debug("Processing GET all affiliations request")

	err := getAffiliations(ctx, caller, caname)
	if err != nil {
		return err
	}

	return nil
}

func processGetAffiliationRequest(ctx *serverRequestContext, caller spi.User, caname string) (interface{}, error) {
	log.Debug("Processing GET affiliation request")

	affiliation, err := ctx.GetVar("affiliation")
	if err != nil {
		return nil, err
	}

	resp, err := getAffiliation(ctx, caller, affiliation, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getAffiliations(ctx *serverRequestContext, caller spi.User, caname string) error {
	log.Debug("Requesting all affiliations that the caller is authorized view")
	var err error

	w := ctx.resp
	flusher, _ := w.(http.Flusher)

	err = ctx.HasRole(attrAffiliationMgr)
	if err != nil {
		return err
	}

	// Get the number of identities to return back to client in a chunk based on the environment variable
	// If environment variable not set, default to 100 identities
	numberOfAffiliations := os.Getenv("FABRIC_CA_SERVER_MAX_AFFILIATIONS_PER_CHUNK")
	var numAffiliations int
	if numberOfAffiliations == "" {
		numAffiliations = 100
	} else {
		numAffiliations, err = strconv.Atoi(numberOfAffiliations)
		if err != nil {
			return newHTTPErr(500, ErrGettingAffiliation, "Incorrect format specified for environment variable 'FABRIC_CA_SERVER_MAX_AFFILIATIONS_PER_CHUNK', an integer value is required: %s", err)
		}
	}

	registry := ctx.ca.registry
	callerAff := GetUserAffiliation(caller)
	rows, err := registry.GetAllAffiliations(callerAff)
	if err != nil {
		return newHTTPErr(500, ErrGettingUser, "Failed to get affiliation: %s", err)
	}

	w.Write([]byte(`{"affiliations":[`))

	rowNumber := 0
	for rows.Next() {
		rowNumber++
		var aff AffiliationRecord
		err := rows.StructScan(&aff)
		if err != nil {
			return newHTTPErr(500, ErrGettingAffiliation, "Failed to get read row: %s", err)
		}

		if rowNumber > 1 {
			w.Write([]byte(","))
		}

		affInfo := api.AffiliationInfo{
			Name: aff.Name,
		}

		resp, err := util.Marshal(affInfo, "identities info")
		if err != nil {
			return newHTTPErr(500, ErrGettingUser, "Failed to marshal identity info: %s", err)
		}
		w.Write(resp)

		// If hit the number of identities requested then flush
		if rowNumber%numAffiliations == 0 {
			flusher.Flush() // Trigger "chunked" encoding and send a chunk...
		}
	}

	// Close the JSON object
	w.Write([]byte(fmt.Sprintf("], \"caname\":\"%s\"}", caname)))
	flusher.Flush()

	return nil
}

func getAffiliation(ctx *serverRequestContext, caller spi.User, requestedAffiliation, caname string) (*api.AffiliationResponse, error) {
	log.Debugf("Requesting affiliation '%s'", requestedAffiliation)

	err := ctx.HasRole(attrAffiliationMgr)
	if err != nil {
		return nil, err
	}

	registry := ctx.ca.registry
	err = ctx.ContainsAffiliation(requestedAffiliation)
	if err != nil {
		return nil, err
	}
	affiliation, err := registry.GetAffiliation(requestedAffiliation)
	if err != nil {
		return nil, err
	}

	resp := &api.AffiliationResponse{
		CAName: caname,
	}
	resp.Info.Name = affiliation.GetName()

	return resp, nil
}

func processAffiliationDeleteRequest(ctx *serverRequestContext, caname string) (*api.RemoveAffiliationResponse, error) {
	log.Debug("Processing DELETE request")

	// TODO

	return nil, errors.New("Not Implemented")
}

func processAffiliationPostRequest(ctx *serverRequestContext, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing POST request")

	// TODO

	return nil, errors.New("Not Implemented")
}

func processAffiliationPutRequest(ctx *serverRequestContext, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing PUT request")

	// TODO

	return nil, errors.New("Not Implemented")
}
