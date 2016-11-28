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
	"errors"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

func newIdentity(client *Client, name string, key []byte, cert []byte) *Identity {
	id := new(Identity)
	id.client = client
	id.Name = name
	id.PublicSigner = newTemporalSigner(key, cert)
	return id
}

// Identity is COP's implementation of an idp.Identity
type Identity struct {
	client       *Client
	Name         string          `json:"name"`
	PublicSigner *TemporalSigner `json:"publicSigner"`
}

// GetName returns the identity name
func (i *Identity) GetName() string {
	return i.Name
}

// GetPublicSigner returns the public signer for this identity
func (i *Identity) GetPublicSigner() idp.TemporalSigner {
	return i.PublicSigner
}

// GetPrivateSigners returns private signers for this identity
func (i *Identity) GetPrivateSigners(req *idp.GetPrivateSignersRequest) ([]idp.TemporalSigner, error) {
	return nil, errors.New("NotImplemented")
}

// GetAttributeNames returns the names of all attributes associated with this identity
func (i *Identity) GetAttributeNames() ([]string, error) {
	return nil, errors.New("NotImplemented")
}

// Revoke the identity associated with 'id'
func (i *Identity) Revoke(req *idp.RevocationRequest) error {
	log.Debugf("Entering identity.Revoke %+v", req)
	reqBody, err := util.Marshal(req, "RevocationRequest")
	if err != nil {
		return err
	}
	_, err2 := i.Post("revoke", reqBody)
	if err2 != nil {
		return err2
	}
	log.Debugf("Successfully revoked %+v", req)
	return nil
}

// RevokeSelf revokes the current identity
func (i *Identity) RevokeSelf() error {
	name := i.GetName()
	log.Debugf("RevokeSelf %s", name)
	serial, aki, err := i.PublicSigner.GetSerial()
	if err != nil {
		return err
	}
	req := &idp.RevocationRequest{
		Name:   name,
		Serial: serial,
		AKI:    aki,
	}
	return i.Revoke(req)
}

// Delete this identity completely and revoke all of it's signers
func (i *Identity) Delete() error {
	return errors.New("NotImplemented")
}

// Store write my identity info to my identity file
func (i *Identity) Store() error {
	return i.StorePath(i.client.GetMyIdentityFile())
}

// StorePath stores my identity info to a file located at path
func (i *Identity) StorePath(path string) error {
	idByte, err := i.Serialize()
	if err != nil {
		return err
	}
	err = util.WriteFile(path, idByte, 0600)
	if err != nil {
		return err
	}
	return nil
}

// Serialize this identity
func (i *Identity) Serialize() ([]byte, error) {
	return util.Marshal(i, "identity")
}

// Post sends arbtrary request body (reqBody) to an endpoint.
// This adds an authorization header which contains the signature
// of this identity over the body and non-signature part of the authorization header.
// The return value is the body of the response.
func (i *Identity) Post(endpoint string, reqBody []byte) ([]byte, error) {
	req, err := i.client.newPost(endpoint, reqBody)
	if err != nil {
		return nil, err
	}
	err = i.addTokenAuthHdr(req, reqBody)
	if err != nil {
		return nil, err
	}
	return i.client.sendPost(req)
}

func (i *Identity) addTokenAuthHdr(req *http.Request, body []byte) error {
	log.Debug("addTokenAuthHdr begin")
	cert := i.GetMyCert()
	key := i.GetMyKey() // TODO: Will change for BCCSP since we can't see key
	if cert == nil || key == nil {
		return cop.NewError(cop.AuthorizationFailure, "Failed to set authorization header token")
	}
	token, tokenerr := util.CreateToken(cert, key, body)
	if tokenerr != nil {
		log.Debug("addTokenAuthHdr failed: CreateToken")
		return cop.WrapError(tokenerr, 1, "test")
	}
	req.Header.Set("authorization", token)
	log.Debug("addTokenAuthHdr success")
	return nil
}

// GetMyCert returns the PEM-encoded cert
func (i *Identity) GetMyCert() []byte {
	return i.PublicSigner.GetMyCert()
}

// GetMyKey returns the PEM-encoded key
func (i *Identity) GetMyKey() []byte {
	return i.PublicSigner.getMyKey()
}
