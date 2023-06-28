/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"math/big"

	"github.com/IBM/mathlib/driver"
)

var onebytes = []byte{
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
}
var onebig = new(big.Int).SetBytes(onebytes)

const ScalarByteSize = 32

func BigToBytes(bi *big.Int) []byte {
	b := bi.Bytes()

	if bi.Sign() >= 0 {
		return append(make([]byte, ScalarByteSize-len(b)), b...)
	}

	twoscomp := new(big.Int).Set(onebig)
	pos := new(big.Int).Neg(bi)
	twoscomp = twoscomp.Sub(twoscomp, pos)
	twoscomp = twoscomp.Add(twoscomp, big.NewInt(1))
	b = twoscomp.Bytes()
	return append(onebytes[:ScalarByteSize-len(b)], b...)
}

type BaseZr struct {
	*big.Int
	Modulus *big.Int
}

func (b *BaseZr) Plus(a driver.Zr) driver.Zr {
	return &BaseZr{new(big.Int).Add(b.Int, a.(*BaseZr).Int), b.Modulus}
}

func (b *BaseZr) Minus(a driver.Zr) driver.Zr {
	return &BaseZr{new(big.Int).Sub(b.Int, a.(*BaseZr).Int), b.Modulus}
}

func (b *BaseZr) Mul(a driver.Zr) driver.Zr {
	prod := new(big.Int).Mul(b.Int, a.(*BaseZr).Int)
	return &BaseZr{prod.Mod(prod, b.Modulus), b.Modulus}
}

func (b *BaseZr) PowMod(x driver.Zr) driver.Zr {
	return &BaseZr{new(big.Int).Exp(b.Int, x.(*BaseZr).Int, b.Modulus), b.Modulus}
}

func (b *BaseZr) Mod(a driver.Zr) {
	b.Int.Mod(b.Int, a.(*BaseZr).Int)
}

func (b *BaseZr) InvModP(p driver.Zr) {
	b.Int.ModInverse(b.Int, p.(*BaseZr).Int)
}

func (b *BaseZr) Bytes() []byte {
	target := b.Int

	if b.Int.Sign() < 0 || b.Int.Cmp(b.Modulus) > 0 {
		target = new(big.Int).Set(b.Int)
		target = target.Mod(target, b.Modulus)
		if target.Sign() < 0 {
			target = target.Add(target, b.Modulus)
		}
	}

	return BigToBytes(target)
}

func (b *BaseZr) Equals(p driver.Zr) bool {
	return b.Int.Cmp(p.(*BaseZr).Int) == 0
}

func (b *BaseZr) Copy() driver.Zr {
	return &BaseZr{new(big.Int).Set(b.Int), b.Modulus}
}

func (b *BaseZr) Clone(a driver.Zr) {
	raw := a.(*BaseZr).Int.Bytes()
	b.Int.SetBytes(raw)
}

func (b *BaseZr) String() string {
	return b.Int.Text(16)
}

func (b *BaseZr) Neg() {
	b.Int.Neg(b.Int)
}
