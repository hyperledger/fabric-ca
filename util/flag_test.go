/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util_test

import (
	"testing"
	"time"

	. "github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// A test struct
type A struct {
	ADur       time.Duration     `help:"Duration"`
	ASlice     []string          `help:"Slice description"`
	AStr       string            `def:"defval" help:"Str1 description"`
	AInt       int               `def:"10" help:"Int1 description"`
	AB         B                 `help:"FB description"`
	AStr2      string            `skip:"true"`
	AIntArray  []int             `help:"IntArray description"`
	AMap       map[string]string `skip:"true"`
	ABPtr      *B                `help:"FBP description"`
	AInterface interface{}       `skip:"true"`
	ABad       ABad              `skip:"true"`
}

// B test struct
type B struct {
	BStr  string `help:"Str description"`
	BInt  int    `skip:"true"`
	BCPtr *C
}

// C test struct
type C struct {
	CBool bool   `def:"true" help:"Bool description"`
	CStr  string `help:"Str description"`
}

type ABad struct{}

type DurBad struct {
	ADur time.Duration `def:"xx" help:"Duration"`
}

type Int64Struct struct {
	Int64Var int64 `def:"3546343826724305832" help:"int64"`
}

func TestRegisterFlags(t *testing.T) {
	tags := map[string]string{
		"help.fb.int": "This is an int field",
	}
	err := RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &A{}, tags)
	assert.NoError(t, err, "failed to RegisterFlags for A")

	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &C{}, tags)
	assert.NoError(t, err, "failed to RegisterFlags for C")

	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &Int64Struct{}, tags)
	assert.NoError(t, err, "Failed to register int64 flag")
}

func TestParseObj(t *testing.T) {
	cb := func(*Field) error { return nil }
	err := ParseObj(&A{}, cb, nil)
	assert.NoError(t, err, "failed to parse A")

	err = ParseObj(&A{}, nil, nil)
	assert.EqualError(t, err, "nil callback", "parse with nil callback should have failed")
}

func TestCheckForMissingValues(t *testing.T) {
	src := &A{
		ADur:      time.Hour,
		AStr:      "AStr",
		AStr2:     "AStr2",
		AIntArray: []int{1, 2, 3},
		AMap:      map[string]string{"Key1": "Val1", "Key2": "Val2"},
		AB: B{
			BStr: "BStr",
			BCPtr: &C{
				CBool: true,
				CStr:  "CStr",
			},
		},
		ABPtr: &B{
			BStr: "BStr",
			BCPtr: &C{
				CBool: false,
				CStr:  "CStr",
			},
		},
		AInterface: &C{
			CStr: "CStr",
		},
	}

	dst := &A{
		AStr2: "dstAStr2",
		AInt:  2,
	}

	CopyMissingValues(src, dst)

	assert.Equal(t, src.AStr, dst.AStr, "failed to copy field AStr")
	assert.Equal(t, src.AB.BStr, dst.AB.BStr, "failed to copy field AB.BStr")
	assert.Equal(t, src.ABPtr.BStr, dst.ABPtr.BStr, "failed to copy field ABPtr.BStr")
	assert.Equal(t, src.ABPtr.BCPtr.CStr, dst.ABPtr.BCPtr.CStr, "failed to copy field ABPtr.BCPtr.CStr")
	assert.Equal(t, src.AMap, dst.AMap, "failed to copy AMap")
	assert.Equal(t, src.AIntArray, dst.AIntArray, "failed to copy AIntArray")
	assert.Equal(t, "dstAStr2", dst.AStr2, "incorrectly replaced AStr2")
	assert.Equal(t, 2, dst.AInt, "incorrectly replaced AInt")
}

func TestRegisterFlagsInvalidArgs(t *testing.T) {
	data := struct{ Field string }{}
	err := RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &data, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Field is missing a help tag")

	data2 := struct{ Field bool }{}
	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &data2, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Field is missing a help tag")

	data3 := struct{ Field int }{}
	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &data3, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Field is missing a help tag")

	data4 := struct{ Field []string }{}
	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &data4, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Field is missing a help tag")

	data5 := struct{ Field time.Duration }{}
	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &data5, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Field is missing a help tag")

	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &DurBad{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid duration value in 'def' tag")

	data6 := struct{ Field float32 }{}
	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &data6, nil)
	assert.NoError(t, err)
}
