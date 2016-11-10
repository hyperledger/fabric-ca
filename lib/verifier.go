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
	"github.com/hyperledger/fabric-cop/util"
)

func newVerifier(cert []byte) Verifier {
	return Verifier{cert}
}

// Verifier implements the idp.Verifier interface
type Verifier struct {
	Cert []byte `json:"cert"`
}

// VerifySelf verifies myself
func (v *Verifier) VerifySelf() error {
	return errors.New("NotImplemented")
}

// Verify a signature over some message
func (v *Verifier) Verify(msg []byte, sig []byte) error {
	return errors.New("NotImplemented")
}

// VerifyOpts verifies a signature over some message with options
func (v *Verifier) VerifyOpts(msg []byte, sig []byte, opts idp.SignatureOpts) error {
	return errors.New("NotImplemented")
}

// VerifyAttributes verifies attributes given proofs
func (v *Verifier) VerifyAttributes(proof [][]byte, spec *idp.AttributeProofSpec) error {
	return errors.New("NotImplemented")
}

// Serialize a Verifier
func (v *Verifier) Serialize() ([]byte, error) {
	return util.Marshal(v, "Verifier")
}

// GetMyCert will return certificate in PEM encoding
func (v *Verifier) GetMyCert() []byte {
	return v.Cert
}
