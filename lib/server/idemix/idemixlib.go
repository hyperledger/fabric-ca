/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"
	"fmt"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	math "github.com/IBM/mathlib"
	cidemix "github.com/hyperledger/fabric-ca/lib/common/idemix"
	scheme "github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

// Lib represents idemix library
type Lib interface {
	NewIssuerKey(AttributeNames []string) (ik *idemix.IssuerKey, err error)
	NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*math.Zr) (cred *idemix.Credential, err error)
	CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*math.Zr, epoch int, alg idemix.RevocationAlgorithm) (cri *idemix.CredentialRevocationInformation, err error)
	GenerateLongTermRevocationKey() (pk *ecdsa.PrivateKey, err error)
	RandModOrder() (*math.Zr, error)
}

// libImpl is adapter for idemix library. It implements Lib interface
type libImpl struct {
	idemix *idemix.Idemix
	curve  *math.Curve
}

// NewLib returns an instance of an object that implements Lib interface
func NewLib(curveID cidemix.CurveID) Lib {
	return &libImpl{idemix: cidemix.InstanceForCurve(curveID), curve: cidemix.CurveByID(curveID)}
}

func (i *libImpl) NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*math.Zr) (cred *idemix.Credential, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()

	rand, err := i.curve.Rand()
	if err != nil {
		return nil, errors.Errorf("failed obtaining randomness source: %v", err)
	}

	return i.idemix.NewCredential(key, m, attrs, rand, i.idemix.Translator)
}

func (i *libImpl) RandModOrder() (zr *math.Zr, err error) {
	defer func() {
		r := recover()
		if r != nil {
			fmt.Printf("##########################")
			err = errors.Errorf("failure: %s", r)
		}
	}()

	rand, err := i.curve.Rand()
	if err != nil {
		return nil, errors.Errorf("failed obtaining randomness source: %v", err)
	}
	x := i.curve.NewRandomZr(rand)
	x.Mod(i.curve.GroupOrder)

	return x, nil
}

func (i *libImpl) NewIssuerKey(attributeNames []string) (ik *idemix.IssuerKey, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()

	rand, err := i.curve.Rand()
	if err != nil {
		return nil, errors.Errorf("failed to obtain randomness source: %v", err)
	}
	return i.idemix.NewIssuerKey(attributeNames, rand, i.idemix.Translator)
}

func (i *libImpl) CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*math.Zr, epoch int, alg idemix.RevocationAlgorithm) (cri *idemix.CredentialRevocationInformation, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()

	rand, err := i.curve.Rand()
	if err != nil {
		return nil, errors.Errorf("failed to obtain randomness source: %v", err)
	}

	return i.idemix.CreateCRI(key, unrevokedHandles, epoch, alg, rand, i.idemix.Translator)
}

func (i *libImpl) GenerateLongTermRevocationKey() (pk *ecdsa.PrivateKey, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return scheme.GenerateLongTermRevocationKey()
}
