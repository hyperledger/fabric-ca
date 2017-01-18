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

package tls

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestGetClientTLSConfig(t *testing.T) {
	tlsConfig, err := ioutil.ReadFile("../../testdata/client-config2.json")
	if err != nil {
		t.Errorf("Failed to read in TLS configuration file [error: %s]", err)
	}

	var cfg ClientTLSConfig
	json.Unmarshal(tlsConfig, &cfg)

	tls, err := GetClientTLSConfig(&cfg)
	if err != nil {
		t.Errorf("Failed to get TLS Config [error: %s]", err)
	}

	fmt.Println("tls config: ", tls)
}
