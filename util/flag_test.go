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
	"testing"

	. "github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/pflag"
)

// A test struct
type A struct {
	Str1 string `def:"defval" help:"Str1 description"`
	Int1 int    `def:"10" help:"Int1 description"`
	FB   B      `help:"FB description"`
	Str2 string `skip:"true"`
	Int2 []int  `help:"Int2 description"`
	FBP  *B     `help:"FBP description"`
}

// B test struct
type B struct {
	Str string `help:"Str description"`
	Int int
	FC  C
}

// C test struct
type C struct {
	Bool bool `def:"true" help:"Bool description"`
}

func printit(f *Field) error {
	//fmt.Printf("%+v\n", f)
	return nil
}

func TestRegisterFlags(t *testing.T) {
	tags := map[string]string{
		"help.fb.int": "This is an int field",
	}
	err := RegisterFlags(&pflag.FlagSet{}, &A{}, tags)
	if err != nil {
		t.Errorf("Failed to register flags: %s", err)
	}
}

func TestParseObj(t *testing.T) {
	err := ParseObj(&A{}, printit)
	if err != nil {
		t.Errorf("Failed to parse foo: %s", err)
	}
	err = ParseObj(&A{}, nil)
	if err == nil {
		t.Error("Should have failed to parse but didn't")
	}
}
