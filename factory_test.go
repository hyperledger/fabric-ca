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

package cop

import "testing"

// TestNewClient tests constructing a client
func TestNewClient(t *testing.T) {
	_, err := NewClient(`{"serverAddr":"http://127.0.0.1:8888"}`)
	if err != nil {
		t.Errorf("Failed to create a client: %s", err)
	}
}

// TestNewClient tests constructing a client
func TestNewClientBadConfig(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Error("TestNewClientBadConfig did not fail but should have")
	}
}

func TestNewIdentity(t *testing.T) {
	_, err := NewIdentity()
	if err != nil {
		t.Error("Failed to create identity")
	}
}
