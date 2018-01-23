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
	"strconv"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/spi"
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
	err = ctx.HasRole(attr.AffiliationMgr)
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
	err = ctx.HasRole(attr.AffiliationMgr)
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
		return processGetAllAffiliationsRequest(ctx, caller, caname)
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

func processGetAllAffiliationsRequest(ctx *serverRequestContext, caller spi.User, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing GET all affiliations request")

	resp, err := getAffiliations(ctx, caller, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func processGetAffiliationRequest(ctx *serverRequestContext, caller spi.User, caname string) (*api.AffiliationResponse, error) {
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

func getAffiliations(ctx *serverRequestContext, caller spi.User, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Requesting all affiliations that the caller is authorized view")
	var err error

	registry := ctx.ca.registry
	callerAff := GetUserAffiliation(caller)
	rows, err := registry.GetAllAffiliations(callerAff)
	if err != nil {
		return nil, newHTTPErr(500, ErrGettingUser, "Failed to get affiliation: %s", err)
	}

	an := &affiliationNode{}
	for rows.Next() {
		var aff AffiliationRecord
		err := rows.StructScan(&aff)
		if err != nil {
			return nil, newHTTPErr(500, ErrGettingAffiliation, "Failed to get read row: %s", err)
		}

		an.insertByName(aff.Name)
	}
	root := an.GetRoot()

	resp := &api.AffiliationResponse{
		CAName: caname,
	}
	resp.Name = root.Name
	resp.Affiliations = root.Affiliations
	resp.Identities = root.Identities

	return resp, nil
}

func getAffiliation(ctx *serverRequestContext, caller spi.User, requestedAffiliation, caname string) (*api.AffiliationResponse, error) {
	log.Debugf("Requesting affiliation '%s'", requestedAffiliation)

	registry := ctx.ca.registry
	err := ctx.ContainsAffiliation(requestedAffiliation)
	if err != nil {
		return nil, err
	}

	result, err := registry.GetAffiliationTree(requestedAffiliation)
	if err != nil {
		return nil, newHTTPErr(500, ErrGettingAffiliation, "Failed to get affiliation: %s", err)
	}

	resp, err := getResponse(result, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func processAffiliationDeleteRequest(ctx *serverRequestContext, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing DELETE request")

	if !ctx.ca.Config.Cfg.Affiliations.AllowRemove {
		return nil, newAuthErr(ErrUpdateConfigRemoveAff, "Affiliation removal is disabled")
	}

	removeAffiliation, err := ctx.GetVar("affiliation")
	if err != nil {
		return nil, err
	}
	log.Debugf("Request to remove affiliation '%s'", removeAffiliation)

	callerAff := GetUserAffiliation(ctx.caller)
	if callerAff == removeAffiliation {
		return nil, newAuthErr(ErrUpdateConfigRemoveAff, "Can't remove affiliation '%s' because the caller is associated with this affiliation", removeAffiliation)
	}

	err = ctx.ContainsAffiliation(removeAffiliation)
	if err != nil {
		return nil, err
	}

	force, err := ctx.GetBoolQueryParm("force")
	if err != nil {
		return nil, err
	}

	_, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		httpErr := getHTTPErr(err)
		if httpErr.lcode != 20 {
			return nil, err
		}
	}

	identityRemoval := ctx.ca.Config.Cfg.Identities.AllowRemove
	result, err := ctx.ca.registry.DeleteAffiliation(removeAffiliation, force, identityRemoval, isRegistrar)
	if err != nil {
		return nil, err
	}

	resp, err := getResponse(result, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func processAffiliationPostRequest(ctx *serverRequestContext, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing POST request")

	ctx.endpoint.successRC = 201

	var req api.AddAffiliationRequestNet
	err := ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}

	addAffiliation := req.Name
	log.Debugf("Request to add affiliation '%s'", addAffiliation)

	registry := ctx.ca.registry
	_, err = registry.GetAffiliation(addAffiliation)
	if err == nil {
		return nil, newHTTPErr(400, ErrUpdateConfigAddAff, "Affiliation already exists")
	}

	err = ctx.ContainsAffiliation(addAffiliation)
	if err != nil {
		return nil, err
	}

	force, err := ctx.GetBoolQueryParm("force")
	if err != nil {
		return nil, err
	}

	addAffiliationSlice := strings.Split(addAffiliation, ".")
	var parentAffiliationPath string

	affLevel := ctx.ca.server.levels.Affiliation
	if force {
		// With force option, add any parent affiliations that don't exist
		var affiliationPath string
		for _, addAff := range addAffiliationSlice {
			affiliationPath = affiliationPath + addAff
			err := registry.InsertAffiliation(affiliationPath, parentAffiliationPath, affLevel)
			if err != nil {
				return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "Failed to add affiliations '%s': %s", addAffiliation, err)
			}
			parentAffiliationPath = affiliationPath
			affiliationPath = affiliationPath + "."
		}
	} else {
		// If the affiliation being added has a parent affiliation, check to make sure that parent affiliation exists
		if len(addAffiliationSlice) > 1 {
			parentAffiliationPath = strings.Join(addAffiliationSlice[:len(addAffiliationSlice)-1], ".") // Get the path up until the last affiliation
			_, err = registry.GetAffiliation(parentAffiliationPath)
			if err != nil {
				httpErr := getHTTPErr(err)
				if httpErr.rcode == 400 {
					return nil, newHTTPErr(400, ErrUpdateConfigAddAff, "Parent affiliation does not exist, 'force' option required on request to add affiliation")
				}
				return nil, err
			}
			err := registry.InsertAffiliation(addAffiliation, parentAffiliationPath, affLevel)
			if err != nil {
				return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "Failed to add affiliation '%s': %s", addAffiliation, err)
			}
		} else {
			err := registry.InsertAffiliation(addAffiliation, "", affLevel)
			if err != nil {
				return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "Failed to add affiliation '%s': %s", addAffiliation, err)
			}
		}

	}

	resp := &api.AffiliationResponse{CAName: caname}
	resp.Name = addAffiliation

	return resp, nil
}

func processAffiliationPutRequest(ctx *serverRequestContext, caname string) (*api.AffiliationResponse, error) {
	log.Debug("Processing PUT request")

	modifyAffiliation, err := ctx.GetVar("affiliation")
	if err != nil {
		return nil, err
	}

	var req api.ModifyAffiliationRequestNet
	err = ctx.ReadBody(&req)
	if err != nil {
		return nil, err
	}
	newAffiliation := req.NewName
	log.Debugf("Request to modify affiliation '%s' to '%s'", modifyAffiliation, newAffiliation)

	err = ctx.ContainsAffiliation(modifyAffiliation)
	if err != nil {
		return nil, err
	}

	err = ctx.ContainsAffiliation(newAffiliation)
	if err != nil {
		return nil, err
	}

	force := false
	forceStr := ctx.req.URL.Query().Get("force")
	if forceStr != "" {
		force, err = strconv.ParseBool(forceStr)
		if err != nil {
			return nil, newHTTPErr(500, ErrUpdateConfigAddAff, "The 'force' query parameter value must be a boolean: %s", err)
		}

	}

	_, isRegistrar, err := ctx.isRegistrar()
	if err != nil {
		httpErr := getHTTPErr(err)
		if httpErr.lcode != 20 {
			return nil, err
		}
	}

	registry := ctx.ca.registry
	result, err := registry.ModifyAffiliation(modifyAffiliation, newAffiliation, force, isRegistrar)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to modify affiliation from '%s' to '%s'", modifyAffiliation, newAffiliation))
	}

	resp, err := getResponse(result, caname)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getResponse(result *spi.DbTxResult, caname string) (*api.AffiliationResponse, error) {
	resp := &api.AffiliationResponse{CAName: caname}
	// Get all root affiliation names from the result
	rootNames := getRootAffiliationNames(result.Affiliations)
	if len(rootNames) == 0 {
		return resp, nil
	}
	if len(rootNames) != 1 {
		return nil, errors.Errorf("multiple root affiliations found: %+v", rootNames)
	}
	affInfo := &api.AffiliationInfo{}
	err := fillAffiliationInfo(affInfo, rootNames[0], result, result.Affiliations)
	if err != nil {
		return nil, err
	}
	resp.AffiliationInfo = *affInfo
	return resp, nil
}

// Get all of the root affiliation names from this list of affiliations
func getRootAffiliationNames(affiliations []spi.Affiliation) []string {
	roots := []string{}
	for _, aff1 := range affiliations {
		isRoot := true
		for _, aff2 := range affiliations {
			if isChildAffiliation(aff2.GetName(), aff1.GetName()) {
				isRoot = false
				break
			}
		}
		if isRoot {
			roots = append(roots, aff1.GetName())
		}
	}
	return roots
}

// Fill 'info' with affiliation info associated with affiliation 'name' hierarchically.
// Use 'affiliations' to find child affiliations for this affiliation, and
// 'identities' to find identities associated with this affiliation.
func fillAffiliationInfo(info *api.AffiliationInfo, name string, result *spi.DbTxResult, affiliations []spi.Affiliation) error {
	info.Name = name
	// Add identities which have this affiliation
	identities := []api.IdentityInfo{}
	for _, identity := range result.Identities {
		idAff := strings.Join(identity.GetAffiliationPath(), ".")
		if idAff == name {
			id, err := getIDInfo(identity)
			if err != nil {
				return err
			}
			identities = append(identities, *id)
		}
	}
	if len(identities) > 0 {
		info.Identities = identities
	}
	// Create child affiliations (if any)
	children := []api.AffiliationInfo{}
	var child spi.Affiliation
	for {
		child = nil
		// Search for a child affiliations
		for idx, aff := range affiliations {
			affName := aff.GetName()
			if isChildAffiliation(name, affName) {
				child = aff
				// Remove this child affiliation
				affiliations = append(affiliations[:idx], affiliations[idx+1:]...)
				break
			}
		}
		if child == nil {
			// No more children of this affiliation 'name' found
			break
		}
		// Found a child of affiliation 'name'
		childAff := api.AffiliationInfo{Name: child.GetName()}
		err := fillAffiliationInfo(&childAff, child.GetName(), result, affiliations)
		if err != nil {
			return err
		}
		children = append(children, childAff)
	}
	if len(children) > 0 {
		info.Affiliations = children
	}
	return nil
}

// Determine if the affiliation with name 'child' is a child of affiliation with name 'name'
func isChildAffiliation(name, child string) bool {
	if !strings.HasPrefix(child, name+".") {
		return false
	}
	nameParts := strings.Split(name, ".")
	childParts := strings.Split(child, ".")
	if len(childParts) != len(nameParts)+1 {
		return false
	}
	return true
}

func getIDInfo(user spi.User) (*api.IdentityInfo, error) {
	allAttributes, err := user.GetAttributes(nil)
	if err != nil {
		return nil, err
	}
	return &api.IdentityInfo{
		ID:             user.GetName(),
		Type:           user.GetType(),
		Affiliation:    GetUserAffiliation(user),
		Attributes:     allAttributes,
		MaxEnrollments: user.GetMaxEnrollments(),
	}, nil
}

type affiliationNode struct {
	children map[string]*affiliationNode
}

func (an *affiliationNode) insertByName(name string) {
	an.insertByPath(strings.Split(name, "."))
}

func (an *affiliationNode) insertByPath(path []string) {
	if len(path) == 0 {
		return
	}
	if an.children == nil {
		an.children = map[string]*affiliationNode{}
	}
	node := an.children[path[0]]
	if node == nil {
		node = &affiliationNode{}
		an.children[path[0]] = node
	}
	node.insertByPath(path[1:])
}

func (an *affiliationNode) GetRoot() *api.AffiliationInfo {
	result := &api.AffiliationInfo{}
	an.fill([]string{}, result)
	switch len(result.Affiliations) {
	case 0:
		return nil
	case 1:
		return &result.Affiliations[0]
	default:
		return result
	}
}

func (an *affiliationNode) fill(path []string, ai *api.AffiliationInfo) {
	ai.Name = strings.Join(path, ".")
	if len(an.children) > 0 {
		ai.Affiliations = make([]api.AffiliationInfo, len(an.children))
		idx := 0
		for key, child := range an.children {
			child.fill(append(path, key), &ai.Affiliations[idx])
			idx++
		}
	}
}
