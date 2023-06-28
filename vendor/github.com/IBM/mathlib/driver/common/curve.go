/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/IBM/mathlib/driver"
)

type CurveBase struct {
	Modulus *big.Int
}

func (c *CurveBase) ModNeg(a1, m driver.Zr) driver.Zr {
	res := new(big.Int).Sub(m.(*BaseZr).Int, a1.(*BaseZr).Int)
	res.Mod(res, m.(*BaseZr).Int)

	return &BaseZr{Int: res, Modulus: c.Modulus}
}

func (c *CurveBase) ModMul(a1, b1, m driver.Zr) driver.Zr {
	res := new(big.Int).Mul(a1.(*BaseZr).Int, b1.(*BaseZr).Int)
	res.Mod(res, m.(*BaseZr).Int)

	return &BaseZr{Int: res, Modulus: c.Modulus}
}

func (c *CurveBase) ModSub(a1, b1, m driver.Zr) driver.Zr {
	res := new(big.Int).Sub(a1.(*BaseZr).Int, b1.(*BaseZr).Int)
	res.Mod(res, m.(*BaseZr).Int)

	return &BaseZr{Int: res, Modulus: c.Modulus}
}

func (c *CurveBase) ModAdd(a1, b1, m driver.Zr) driver.Zr {
	res := new(big.Int).Add(a1.(*BaseZr).Int, b1.(*BaseZr).Int)
	res.Mod(res, m.(*BaseZr).Int)

	return &BaseZr{Int: res, Modulus: c.Modulus}
}

func (c *CurveBase) GroupOrder() driver.Zr {
	return &BaseZr{Int: c.Modulus, Modulus: c.Modulus}
}

func (c *CurveBase) NewZrFromBytes(b []byte) driver.Zr {
	return &BaseZr{Int: new(big.Int).SetBytes(b), Modulus: c.Modulus}
}

func (c *CurveBase) NewZrFromInt(i int64) driver.Zr {
	return &BaseZr{Int: big.NewInt(i), Modulus: c.Modulus}
}

func (c *CurveBase) NewRandomZr(rng io.Reader) driver.Zr {
	bi, err := rand.Int(rng, c.Modulus)
	if err != nil {
		panic(err)
	}

	return &BaseZr{Int: bi, Modulus: c.Modulus}
}

func (c *CurveBase) HashToZr(data []byte) driver.Zr {
	digest := sha256.Sum256(data)
	digestBig := new(big.Int).SetBytes(digest[:])
	digestBig.Mod(digestBig, c.Modulus)
	return &BaseZr{Int: digestBig, Modulus: c.Modulus}
}

func (p *CurveBase) Rand() (io.Reader, error) {
	return rand.Reader, nil
}
