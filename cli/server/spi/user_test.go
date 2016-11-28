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

import (
	"testing"

	"github.com/hyperledger/fabric-cop/idp"
)

func TestGetAttributes(t *testing.T) {
	userInfo := &UserInfo{"TestUser1", "User1", "Client", []idp.Attribute{idp.Attribute{Name: "testName", Value: "testValue"}}}
	user := NewUser(userInfo)
	attributes, err := user.GetAttributes()
	if err != nil {
		t.Error("Error getting attributes of user")
	}
	if attributes[0].Name != "testName" {
		t.Error("Attribute name does not match, expected 'testName'")
	}
}
