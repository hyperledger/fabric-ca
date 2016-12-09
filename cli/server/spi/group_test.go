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

/*
 * This file contains interfaces for the COP library.
 * COP provides police-like security functions for Hyperledger Fabric.
 */

package spi

import "testing"

func TestGetName(t *testing.T) {
	groupInfo := &GroupInfo{Name: "Bank_a", ParentID: "Bank"}
	group := NewGroup(groupInfo)
	name := group.GetName()

	if name != "Bank_a" {
		t.Error("Name does not match, expected 'Bank_a'")
	}
}

func TestGetParent(t *testing.T) {
	groupInfo := &GroupInfo{Name: "Bank_a", ParentID: "Bank"}
	group := NewGroup(groupInfo)
	name := group.GetParent()

	if name != "Bank" {
		t.Error("Parent name does not match, expected 'Bank'")
	}
}
