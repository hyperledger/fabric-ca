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

package lib

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
)

func newIdentity(client *Client, name string, key bccsp.Key, cert []byte) *Identity {
	id := new(Identity)
	id.name = name
	id.ecert = newSigner(key, cert, id)
	id.client = client
	if client != nil {
		id.CSP = client.csp
	} else {
		id.CSP = util.GetDefaultBCCSP()
	}
	return id
}

// Identity is fabric-ca's implementation of an identity
type Identity struct {
	name   string
	ecert  *Signer
	client *Client
	CSP    bccsp.BCCSP
}

// GetName returns the identity name
func (i *Identity) GetName() string {
	return i.name
}

// GetClient returns the client associated with this identity
func (i *Identity) GetClient() *Client {
	return i.client
}

// GetECert returns the enrollment certificate signer for this identity
func (i *Identity) GetECert() *Signer {
	return i.ecert
}

// GetTCertBatch returns a batch of TCerts for this identity
func (i *Identity) GetTCertBatch(req *api.GetTCertBatchRequest) ([]*Signer, error) {
	reqBody, err := util.Marshal(req, "GetTCertBatchRequest")
	if err != nil {
		return nil, err
	}
	err = i.Post("tcert", reqBody, nil)
	if err != nil {
		return nil, err
	}
	// Ignore the contents of the response for now.  They will be processed in the future when we need to
	// support the Go SDK.   We currently have Node and Java SDKs which process this and they are the
	// priority.
	return nil, nil
}

// Register registers a new identity
// @param req The registration request
func (i *Identity) Register(req *api.RegistrationRequest) (rr *api.RegistrationResponse, err error) {
	log.Debugf("Register %+v", req)
	if req.Name == "" {
		return nil, errors.New("Register was called without a Name set")
	}

	reqBody, err := util.Marshal(req, "RegistrationRequest")
	if err != nil {
		return nil, err
	}

	// Send a post to the "register" endpoint with req as body
	resp := &api.RegistrationResponse{}
	err = i.Post("register", reqBody, resp)
	if err != nil {
		return nil, err
	}

	log.Debug("The register request completed successfully")
	return resp, nil
}

// RegisterAndEnroll registers and enrolls an identity and returns the identity
func (i *Identity) RegisterAndEnroll(req *api.RegistrationRequest) (*Identity, error) {
	if i.client == nil {
		return nil, errors.New("No client is associated with this identity")
	}
	rresp, err := i.Register(req)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to register %s", req.Name))
	}
	eresp, err := i.client.Enroll(&api.EnrollmentRequest{
		Name:   req.Name,
		Secret: rresp.Secret,
	})
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("Failed to enroll %s", req.Name))
	}
	return eresp.Identity, nil
}

// Reenroll reenrolls an existing Identity and returns a new Identity
// @param req The reenrollment request
func (i *Identity) Reenroll(req *api.ReenrollmentRequest) (*EnrollmentResponse, error) {
	log.Debugf("Reenrolling %s", util.StructToString(req))

	csrPEM, key, err := i.client.GenCSR(req.CSR, i.GetName())
	if err != nil {
		return nil, err
	}

	reqNet := &api.ReenrollmentRequestNet{
		CAName:   req.CAName,
		AttrReqs: req.AttrReqs,
	}

	// Get the body of the request
	if req.CSR != nil {
		reqNet.SignRequest.Hosts = req.CSR.Hosts
	}
	reqNet.SignRequest.Request = string(csrPEM)
	reqNet.SignRequest.Profile = req.Profile
	reqNet.SignRequest.Label = req.Label

	body, err := util.Marshal(reqNet, "SignRequest")
	if err != nil {
		return nil, err
	}
	var result enrollmentResponseNet
	err = i.Post("reenroll", body, &result)
	if err != nil {
		return nil, err
	}
	return i.client.newEnrollmentResponse(&result, i.GetName(), key)
}

// Revoke the identity associated with 'id'
func (i *Identity) Revoke(req *api.RevocationRequest) (*api.RevocationResponse, error) {
	log.Debugf("Entering identity.Revoke %+v", req)
	reqBody, err := util.Marshal(req, "RevocationRequest")
	if err != nil {
		return nil, err
	}
	var result api.RevocationResponse
	err = i.Post("revoke", reqBody, &result)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully revoked certificates: %+v", req)
	return &result, nil
}

// RevokeSelf revokes the current identity and all certificates
func (i *Identity) RevokeSelf() (*api.RevocationResponse, error) {
	name := i.GetName()
	log.Debugf("RevokeSelf %s", name)
	req := &api.RevocationRequest{
		Name: name,
	}
	return i.Revoke(req)
}

// GenCRL generates CRL
func (i *Identity) GenCRL(req *api.GenCRLRequest) (*api.GenCRLResponse, error) {
	log.Debugf("Entering identity.GenCRL %+v", req)
	reqBody, err := util.Marshal(req, "GenCRLRequest")
	if err != nil {
		return nil, err
	}
	var result api.GenCRLResponse
	err = i.Post("gencrl", reqBody, &result)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully generated CRL: %+v", req)
	return &result, nil
}

// GetIdentity returns information about the requested identity
func (i *Identity) GetIdentity(id, caname string) (*api.GetIDResponse, error) {
	log.Debugf("Entering identity.GetIdentity %s", id)
	result := &api.GetIDResponse{}
	err := i.Get(fmt.Sprintf("identities/%s", id), caname, result)
	if err != nil {
		return nil, err
	}

	log.Debugf("Successfully retrieved identity: %+v", result)
	return result, nil
}

// GetAllIdentities returns all identities that the caller is authorized to see
func (i *Identity) GetAllIdentities(caname string) (*api.GetAllIDsResponse, error) {
	log.Debugf("Entering identity.GetAllIdentities")
	result := &api.GetAllIDsResponse{}
	err := i.Get("identities", caname, result)
	if err != nil {
		return nil, err
	}
	log.Debugf("Successfully retrieved identities: %+v", result)
	return result, nil
}

// Store writes my identity info to disk
func (i *Identity) Store() error {
	if i.client == nil {
		return errors.New("An identity with no client may not be stored")
	}
	return i.client.StoreMyIdentity(i.ecert.cert)
}

// Get sends a get request to an endpoint
func (i *Identity) Get(endpoint, caname string, result interface{}) error {
	req, err := i.client.newGet(endpoint)
	if err != nil {
		return err
	}
	if caname != "" {
		url := req.URL.Query()
		url.Add("ca", caname)
		req.URL.RawQuery = url.Encode()
	}
	err = i.addTokenAuthHdr(req, nil)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

// Post sends arbitrary request body (reqBody) to an endpoint.
// This adds an authorization header which contains the signature
// of this identity over the body and non-signature part of the authorization header.
// The return value is the body of the response.
func (i *Identity) Post(endpoint string, reqBody []byte, result interface{}) error {
	req, err := i.client.newPost(endpoint, reqBody)
	if err != nil {
		return err
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return err
	}
	return i.client.SendReq(req, result)
}

func (i *Identity) addTokenAuthHdr(req *http.Request, body []byte) error {
	log.Debug("Adding token-based authorization header")
	cert := i.ecert.cert
	key := i.ecert.key
	token, err := util.CreateToken(i.CSP, cert, key, body)
	if err != nil {
		return errors.WithMessage(err, "Failed to add token authorization header")
	}
	req.Header.Set("authorization", token)
	return nil
}
