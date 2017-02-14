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
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
)

const (
	testYaml = "test.yaml"
)

var (
	longUserName = string(make([]byte, 10250))
)

// TestInit tests fabric-ca-server init
func TestInit(t *testing.T) {
	os.Unsetenv(homeEnvVar)
	err := RunMain([]string{cmdName, "init", "-b", "admin:adminpw"})
	if err != nil {
		t.Errorf("server init failed: %s", err)
	}
	err = RunMain([]string{cmdName, "init", "-d"})
	if err != nil {
		t.Errorf("server init -d failed: %s", err)
	}
	err = RunMain([]string{cmdName, "init", "-c", testYaml,
		"-b", fmt.Sprintf("%s:foo", longUserName)})
	if err == nil {
		t.Errorf("server init -b longUserName should have failed")
	}
	err = RunMain([]string{cmdName, "init", "-c", testYaml, "-b", "user:"})
	if err == nil {
		t.Errorf("server init empty password should have failed")
	}
	err = RunMain([]string{cmdName, "init", "-c", testYaml, "-b", "user"})
	if err == nil {
		t.Errorf("server init no colon should have failed")
	}
	err = RunMain([]string{cmdName, "init", "-c", testYaml, "-b", "foo:bar"})
	if err != nil {
		t.Errorf("server init -c -b failed: %s", err)
	}
}

// TestStart tests fabric-ca-server start
func TestStart(t *testing.T) {
	blockingStart = false
	err := RunMain([]string{cmdName, "start"})
	if err != nil {
		t.Errorf("server start failed: %s", err)
	}
}

// TestBogus tests a negative test case
func TestBogus(t *testing.T) {
	err := RunMain([]string{cmdName, "bogus"})
	if err == nil {
		t.Errorf("server bogus passed but should have failed")
	}
}

func TestClean(t *testing.T) {
	defYaml := util.GetDefaultConfigFile(cmdName)
	os.Remove(defYaml)
	os.Remove(testYaml)
	os.Remove("ca-key.pem")
	os.Remove("ca-cert.pem")
	os.Remove("fabric-ca-server.db")
}
