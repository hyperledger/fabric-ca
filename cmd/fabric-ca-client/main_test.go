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

package main

import (
	"os"
	"testing"
)

const (
	testYaml = "test.yaml"
)

var (
	defYaml string
)

// TestEnroll tests fabric-ca-client enroll
func TestEnroll(t *testing.T) {
	defYaml = getDefaultConfigFile()

	// Negative test case, enroll command without username/password
	err := RunMain([]string{cmdName, "enroll", "-d", "--url", "http://localhost:7054"})
	if err == nil {
		t.Errorf("No username/password provided, should have errored")
	}

	err = RunMain([]string{cmdName, "enroll", "-u", "foo:bar"})
	if err != nil {
		t.Errorf("client enroll -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "--url", "http://localhost:7054", "-u", "foo:bar"})
	if err != nil {
		t.Errorf("client enroll --url -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "enroll", "-c", testYaml, "-u", "foo:bar"})
	if err != nil {
		t.Errorf("client enroll -c -u failed: %s", err)
	}

	os.RemoveAll(defYaml)
	os.Remove(testYaml)
}

// TestReenroll tests fabric-ca-client reenroll
func TestReenroll(t *testing.T) {
	err := RunMain([]string{cmdName, "reenroll", "-f", "csr.json"})
	if err != nil {
		t.Errorf("client reenroll -f failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll"})
	if err != nil {
		t.Errorf("client reenroll failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "--url", "http://localhost:7054"})
	if err != nil {
		t.Errorf("client reenroll --url failed: %s", err)
	}

	err = RunMain([]string{cmdName, "reenroll", "-c", testYaml})
	if err != nil {
		t.Errorf("client reenroll -c failed: %s", err)
	}

	os.RemoveAll(defYaml)
	os.Remove(testYaml)
}

// TestRegister tests fabric-ca-client register
func TestRegister(t *testing.T) {
	err := RunMain([]string{cmdName, "register", "-f", "regRequest.json"})
	if err != nil {
		t.Errorf("client register -f failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "--url", "http://localhost:7054", "-f", "regRequest.json"})
	if err != nil {
		t.Errorf("client register --url -f failed: %s", err)
	}

	err = RunMain([]string{cmdName, "register", "-c", testYaml, "-f", "regRequest.json"})
	if err != nil {
		t.Errorf("client register -c -f failed: %s", err)
	}

	os.RemoveAll(defYaml)
	os.Remove(testYaml)
}

// TestRevoke tests fabric-ca-client revoke
func TestRevoke(t *testing.T) {
	err := RunMain([]string{cmdName, "revoke", "-u", "foo"})
	if err != nil {
		t.Errorf("client revoke -u failed: %s", err)
	}

	err = RunMain([]string{cmdName, "revoke"})
	if err != nil {
		t.Errorf("client revoke: %s", err)
	}

	err = RunMain([]string{cmdName, "revoke", "--url", "http://localhost:7054"})
	if err != nil {
		t.Errorf("client revoke --url failed: %s", err)
	}

	err = RunMain([]string{cmdName, "revoke", "-c", testYaml})
	if err != nil {
		t.Errorf("client revoke -c failed: %s", err)
	}

	os.RemoveAll(defYaml)
	os.Remove(testYaml)
}

// TestBogus tests a negative test case
func TestBogus(t *testing.T) {
	err := RunMain([]string{cmdName, "bogus"})
	if err == nil {
		t.Errorf("client bogus passed but should have failed")
	}
}
