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

package mocks

import (
	"hash"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/stretchr/testify/mock"
)

// BCCSP mocks a BCCSP to be used in the util package
type BCCSP struct {
	mock.Mock
}

// KeyGen generates a key using opts.
func (*BCCSP) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	panic("implement me")
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (*BCCSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	panic("implement me")
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (m *BCCSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	args := m.Called(raw, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(bccsp.Key), args.Error(1)
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (*BCCSP) GetKey(ski []byte) (k bccsp.Key, err error) {
	panic("implement me")
}

// Hash hashes messages msg using options opts.
// If opts is nil, the default hash function will be used.
func (*BCCSP) Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error) {
	panic("implement me")
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil, the default hash function will be returned.
func (*BCCSP) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	panic("implement me")
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the algorithm used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (*BCCSP) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	panic("implement me")
}

// Verify verifies signature against key k and digest
// The opts argument should be appropriate for the algorithm used.
func (*BCCSP) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	panic("implement me")
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the algorithm used.
func (*BCCSP) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	panic("implement me")
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the algorithm used.
func (*BCCSP) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	panic("implement me")
}
