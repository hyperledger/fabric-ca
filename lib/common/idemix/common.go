/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"fmt"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
)

// CurveID defines the index of the possible idemix curves
type CurveID uint8

const (
	// Undefined is used to indicate that no curve has been defined
	Undefined CurveID = iota
	// FP256BN is an AMCL implementation of BN256 and its corresponding finite field
	FP256BN
	// Gurvy is an implementation of gnark-crypto of BN254 and its corresponding finite field
	Gurvy
	// FP256BNMiracl is another AMCL implementation of BN256 and its corresponding finite field
	FP256BNMiracl
)

const (
	// DefaultIdemixCurve is the curve picked by Fabric-CA at default
	DefaultIdemixCurve = "amcl.Fp256bn"
)

// CurveIDs defines a collection of CurveIDs
type CurveIDs []CurveID

var (
	translators = [...]idemix.Translator{&amcl.Fp256bn{C: math.Curves[0]}, &amcl.Gurvy{C: math.Curves[1]}, &amcl.Fp256bnMiracl{C: math.Curves[2]}}
	// Curves lists all idemix curves that can be picked by Fabric-CA
	Curves = CurveIDs{FP256BN, Gurvy, FP256BNMiracl}

	// curvesByName maps the names of the curves as they appear in the configuration to their CurveID enum.
	curvesByName = map[string]CurveID{
		DefaultIdemixCurve:   FP256BN,
		"gurvy.Bn254":        Gurvy,
		"amcl.Fp256Miraclbn": FP256BNMiracl,
	}
)

// ByName returns CurveID with the corresponding name, or Undefined
func (cids CurveIDs) ByName(name string) CurveID {
	return curvesByName[name]
}

// ByID returns the name of the given CurveID or an empty string
func (cids CurveIDs) ByID(curveID CurveID) string {
	for name, currentCurveID := range curvesByName {
		if currentCurveID == curveID {
			return name
		}
	}
	return ""
}

// Names returns the names of the curves according to their order
func (cids CurveIDs) Names() []string {
	var res []string
	for _, curveID := range curvesByName {
		res = append(res, cids.ByID(curveID))
	}
	return res
}

// InstanceForCurve returns an Idemix instance that uses the given CurveID
func InstanceForCurve(id CurveID) *idemix.Idemix {
	if id == Undefined {
		panic("undefined curve")
	}
	id--
	if int(id) >= len(math.Curves) {
		panic(fmt.Sprintf("CurveID must be in [0,%d]", len(math.Curves)-1))
	}

	idemix := &idemix.Idemix{
		Curve:      math.Curves[int(id)],
		Translator: translators[int(id)],
	}

	return idemix
}

// CurveByID returns the Mathlib curve that corresponds to the given CurveID
func CurveByID(id CurveID) *math.Curve {
	if id == Undefined {
		panic("undefined curve")
	}
	id--
	if int(id) >= len(math.Curves) {
		panic(fmt.Sprintf("CurveID must be in [0,%d]", len(math.Curves)-1))
	}
	return math.Curves[int(id)]
}
