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

package api

import (
	"testing"

	cfsslErr "github.com/cloudflare/cfssl/errors"
)

func TestNewError(t *testing.T) {
	err := NewError(InvalidProviderName, "invalid factory name: %s", "foo")
	if err == nil {
		t.Error("Error creation failed.")
	}
	if err.Error() == "" {
		t.Errorf("returned empty error")
	}
	if err.Code() != 100004 {
		t.Errorf("invalid error code; expecting 100003 but found %d", err.ErrorCode)
	}
	t.Logf("TestNew: %v", err)
}

func TestWrapError(t *testing.T) {
	err := NewError(InvalidProviderName, "invalid factory name: %s", "foo")
	if err == nil {
		t.Error("Error creation failed.")
	}
	err = WrapError(err, NotImplemented, "feature 'foo' has not implemented")
	if err == nil {
		t.Error("Wrap creation failed.")
	}
}

func TestCfsslWrapError(t *testing.T) {
	err := cfsslErr.New(cfsslErr.CertificateError, cfsslErr.Unknown)
	if err == nil {
		t.Fatal("CFSSL Error creation failed.")
	}
	err2 := WrapCFSSLError(err, 1, "wrapped error")
	if err2 == nil {
		t.Fatal("COP Error creation failed.")
	}
}
