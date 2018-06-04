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

package util_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/lib"
	. "github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// A test struct
type A struct {
	ADur        time.Duration     `help:"Duration"`
	ASlice      []string          `help:"Slice description"`
	AStr        string            `def:"defval" help:"Str1 description"`
	AInt        int               `def:"10" help:"Int1 description"`
	AB          B                 `help:"FB description"`
	AStr2       string            `skip:"true"`
	AIntArray   []int             `help:"IntArray description"`
	AMap        map[string]string `skip:"true"`
	ABPtr       *B                `help:"FBP description"`
	AInterface  interface{}       `skip:"true"`
	aUnexported string
	ABad        ABad `skip:"true"`
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

type ABad struct {
}

type DurBad struct {
	ADur time.Duration `def:"xx" help:"Duration"`
}

type Int64Struct struct {
	Int64Var int64 `def:"3546343826724305832" help:"int64"`
}

func printit(f *Field) error {
	//fmt.Printf("%+v\n", f)
	return nil
}

func TestRegisterFlags(t *testing.T) {
	tags := map[string]string{
		"help.fb.int": "This is an int field",
	}
	err := RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &A{}, tags)
	if err != nil {
		t.Errorf("Failed to register flags: %s", err)
	}
	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &C{}, tags)
	if err != nil {
		t.Errorf("Failed to register flags: %s", err)
	}
	err = RegisterFlags(viper.GetViper(), &pflag.FlagSet{}, &Int64Struct{}, tags)
	assert.NoError(t, err, "Failed to register int64 flag")
}

func TestParseObj(t *testing.T) {
	err := ParseObj(&A{}, printit, nil)
	if err != nil {
		t.Errorf("Failed to parse foo: %s", err)
	}
	err = ParseObj(&A{}, nil, nil)
	if err == nil {
		t.Error("Should have failed to parse but didn't")
	}
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

	if src.AStr != dst.AStr {
		t.Error("Failed to copy field AStr")
	}

	if src.AB.BStr != dst.AB.BStr {
		t.Error("Failed to copy field AB.BStr")
	}

	if src.ABPtr.BStr != dst.ABPtr.BStr {
		t.Error("Failed to copy field ABPtr.BStr")
	}

	if src.ABPtr.BCPtr.CStr != dst.ABPtr.BCPtr.CStr {
		t.Error("Failed to copy field ABPtr.BCPtr.CStr")
	}

	if !reflect.DeepEqual(src.AMap, dst.AMap) {
		t.Errorf("Failed to copy AMap: src=%+v, dst=%+v", src.AMap, dst.AMap)
	}

	for i := range src.AIntArray {
		sv := src.AIntArray[i]
		dv := dst.AIntArray[i]
		if sv != dv {
			t.Errorf("Failed to copy element %d of Int2 array (%d != %d)", i, sv, dv)
		}
	}

	if dst.AStr2 != "dstAStr2" {
		t.Errorf("Incorrectly replaced AStr2 with %s", dst.AStr2)
	}

	if dst.AInt != 2 {
		t.Errorf("Incorrectly replaced AInt with %d", dst.AInt)
	}
}

func TestViperUnmarshal(t *testing.T) {
	var err error

	cfg := &lib.CAConfig{}
	vp := viper.New()
	vp.SetConfigFile("../testdata/testviperunmarshal.yaml")
	err = vp.ReadInConfig()
	if err != nil {
		t.Errorf("Failed to read config file: %s", err)
	}

	sliceFields := []string{
		"db.tls",
	}
	err = ViperUnmarshal(cfg, sliceFields, vp)
	if err == nil {
		t.Error("Should have resulted in an error, as tls can't be casted to type string array")
	}

	sliceFields = []string{
		"db.tls.certfiles",
	}
	err = ViperUnmarshal(cfg, sliceFields, vp)
	if err != nil {
		t.Error("Failed to correctly process valid path to be type string array: ", err)
	}
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
