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
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
)

const (
	initYaml  = "i.yaml"
	startYaml = "s.yaml"
)

var (
	longUserName = util.RandomString(1025)
)

var (
	longFileName = util.RandomString(261)
)

// Create a config element in unexpected format
var badSyntaxYaml = "bad.yaml"

// Unsupported file type
var unsupportedFileType = "config.txt"

type TestData struct {
	input    []string // input
	expected string   // expected result
}

// checkTest validates success cases
func checkTest(in *TestData, t *testing.T) {
	err := RunMain(in.input)
	if err != nil {
		t.Errorf("FAILED:\n \tin: %v;\n \tout: %v\n \texpected: SUCCESS\n", in.input, err.Error())
	}
}

// errorTest validates error cases
func errorTest(in *TestData, t *testing.T) {
	err := RunMain(in.input)
	if err != nil {
		matched, _ := regexp.MatchString(in.expected, err.Error())
		if !matched {
			t.Errorf("FAILED:\n \tin: %v;\n \tout: %v;\n \texpected: %v\n", in.input, err.Error(), in.expected)
		}
	} else {
		t.Errorf("FAILED:\n \tin: %v;\n \tout: <nil>\n \texpected: %v\n", in.input, in.expected)
	}
}

func TestErrors(t *testing.T) {
	os.Unsetenv(homeEnvVar)
	_ = ioutil.WriteFile(badSyntaxYaml, []byte("signing: true\n"), 0644)

	errorCases := []TestData{
		{[]string{cmdName, "init", "-c", initYaml}, "option is required"},
		{[]string{cmdName, "init", "-b", "user:pass", "ca.key"}, "too many arguments"},
		{[]string{cmdName, "init", "-b", "user::"}, "Failed to read"},
		{[]string{cmdName, "init", "-c", badSyntaxYaml, "-b", "user:pass"}, "Incorrect format"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", fmt.Sprintf("%s:foo", longUserName)}, "than 1024 characters"},
		{[]string{cmdName, "init", "-c", fmt.Sprintf("%s.yaml", longFileName), "-b", "user:pass"}, "file name too long"},
		{[]string{cmdName, "init", "-c", unsupportedFileType}, "Unsupported Config Type"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", "user"}, "missing a colon"},
		{[]string{cmdName, "init", "-c", initYaml, "-b", "user:"}, "empty password"},
		{[]string{cmdName, "bogus", "-c", initYaml, "-b", "user:pass"}, "unknown command"},
		{[]string{cmdName, "start", "-c"}, "needs an argument:"},
		{[]string{cmdName, "start", "-c", startYaml, "-b", "user:pass", "ca.key"}, "too many arguments"},
	}

	for _, e := range errorCases {
		errorTest(&e, t)
		_ = os.Remove(initYaml)
	}
}

func TestValid(t *testing.T) {
	os.Unsetenv(homeEnvVar)
	blockingStart = false

	os.Setenv("CA_CFG_PATH", ".")
	validCases := []TestData{
		{[]string{cmdName, "init", "-b", "admin:a:d:m:i:n:p:w"}, ""},
		{[]string{cmdName, "init", "-d"}, ""},
		{[]string{cmdName, "start", "-c", startYaml}, ""},
	}

	for _, v := range validCases {
		checkTest(&v, t)
	}
}

func TestClean(t *testing.T) {
	defYaml := util.GetDefaultConfigFile(cmdName)
	os.Remove(defYaml)
	os.Remove(initYaml)
	os.Remove(startYaml)
	os.Remove(badSyntaxYaml)
	os.Remove(unsupportedFileType)
	os.Remove("ca-key.pem")
	os.Remove("ca-cert.pem")
	os.Remove("fabric-ca-server.db")
}
