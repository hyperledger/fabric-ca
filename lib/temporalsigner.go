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

import "errors"

func newTemporalSigner(key []byte, cert []byte) *TemporalSigner {
	return &TemporalSigner{newSigner(key, cert)}
}

// TemporalSigner implements idp.TemporalSigner
type TemporalSigner struct {
	Signer
}

// Renew renews the signer's certificate
func (ts *TemporalSigner) Renew() error {
	return errors.New("NotImplemented")
}

// Revoke revokes the signer's certificate
func (ts *TemporalSigner) Revoke() error {
	return errors.New("NotImplemented")
}
