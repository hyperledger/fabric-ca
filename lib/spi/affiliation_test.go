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

package spi

import "testing"

func TestGetName(t *testing.T) {
	aff := NewAffiliation("Bank_a", "1234", 0)
	name := aff.GetName()

	if name != "Bank_a" {
		t.Error("Name does not match, expected 'Bank_a'")
	}
}

func TestGetPrekey(t *testing.T) {
	aff := NewAffiliation("Bank_a", "1234", 0)
	name := aff.GetPrekey()

	if name != "1234" {
		t.Error("Prekey does not match, expected '1234'")
	}
}

func TestGetLevel(t *testing.T) {
	aff := NewAffiliation("Bank_a", "1234", 2)
	level := aff.GetLevel()

	if level != 2 {
		t.Error("Level does not match, expected '2'")
	}
}
