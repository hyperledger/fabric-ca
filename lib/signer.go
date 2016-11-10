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

	"github.com/hyperledger/fabric-cop/idp"
)

func newSigner(key []byte, cert []byte) Signer {
	return Signer{newVerifier(cert), key}
}

// Signer implements idp.Signer interface
type Signer struct {
	Verifier
	Key []byte `json:"key"`
}

// Sign the message
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	return nil, errors.New("NotImplemented")
}

// SignOpts the message with options
func (s *Signer) SignOpts(msg []byte, opts idp.SignatureOpts) ([]byte, error) {
	return nil, errors.New("NotImplemented")
}

// NewAttributeProof creates a proof for an attribute
func (s *Signer) NewAttributeProof(spec *idp.AttributeProofSpec) (proof []byte, err error) {
	return nil, errors.New("NotImplemented")
}

// TODO:
func (s *Signer) getMyKey() []byte {
	return s.Key
}
