/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"github.com/hyperledger/fabric-amcl/amcl"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric/idemix"
)

// Lib represents idemix library
type Lib interface {
	NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (*idemix.IssuerKey, error)
	NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (*idemix.Credential, error)
	GetRand() (*amcl.RAND, error)
	RandModOrder(rng *amcl.RAND) *fp256bn.BIG
	// BigToBytes(big *fp256bn.BIG) []byte
	// HashModOrder(data []byte) *fp256bn.BIG
}

// libImpl is adapter for idemix library. It implements Lib interface
type libImpl struct{}

// NewLib returns an instance of an object that implements Lib interface
func NewLib() Lib {
	return &libImpl{}
}

func (i *libImpl) GetRand() (*amcl.RAND, error) {
	return idemix.GetRand()
}
func (i *libImpl) NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (*idemix.Credential, error) {
	return idemix.NewCredential(key, m, attrs, rng)
}
func (i *libImpl) RandModOrder(rng *amcl.RAND) *fp256bn.BIG {
	return idemix.RandModOrder(rng)
}
func (i *libImpl) NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (*idemix.IssuerKey, error) {
	return idemix.NewIssuerKey(AttributeNames, rng)
}

// func (i *libImpl) BigToBytes(big *fp256bn.BIG) []byte {
// 	return idemix.BigToBytes(big)
// }
// func (i *libImpl) HashModOrder(data []byte) *fp256bn.BIG {
// 	return idemix.HashModOrder(data)
// }
