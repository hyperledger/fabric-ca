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

package csp_test

import (
	"path"
	"testing"

	"github.com/hyperledger/fabric-ca/lib/csp"
	"github.com/hyperledger/fabric/bccsp"
)

func TestBCCSP(t *testing.T) {
	_, err := csp.Get(nil)
	if err != nil {
		t.Fatalf("Failed to get default BCCSP instance: %s", err)
	}
	_, err = csp.Get(&csp.Config{})
	if err == nil {
		t.Fatal("Empty config should have failed but didn't")
	}
	cfg := &csp.Config{SW: &csp.SWConfig{KeyStoreDir: getTestFile("ks")}}
	bccsp, err := csp.Get(cfg)
	if err != nil {
		t.Fatalf("Failed to get test BCCSP instance: %s", err)
	}
	// GetSignerFromSKIFile test cases
	// 1st is positive and others are negative
	getSignerFromSKIFile("ec-key.ski", bccsp, "", t)
	getSignerFromSKIFile("bogus-file", bccsp, "bad file", t)
	getSignerFromSKIFile("", bccsp, "no file", t)
	getSignerFromSKIFile("ec-key.ski", nil, "nil bccsp", t)
}

func getSignerFromSKIFile(name string, bccsp bccsp.BCCSP, expectFailure string, t *testing.T) {
	file := getTestFile(name)
	_, err := csp.GetSignerFromSKIFile(file, bccsp)
	if err != nil {
		if expectFailure == "" {
			t.Errorf("Failed in GetSignerFromSKIFIle for file %s: %s", name, err)
		}
	} else {
		if expectFailure != "" {
			t.Errorf("Expected failure but passed: %s", expectFailure)
		}
	}
}

func getTestFile(name string) string {
	return path.Join(".", "testdata", name)
}
