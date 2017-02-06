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

package util_test

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
)

func TestGetCommandLineOptValue(t *testing.T) {
	testGetCommandLineOptValue(t,
		[]string{"fabric-ca", "client", "enroll", "-config", "myconfig.json"},
		"-config",
		true,
		"myconfig.json",
		[]string{"fabric-ca", "client", "enroll"})
	testGetCommandLineOptValue(t,
		[]string{"fabric-ca", "client", "-config", "myconfig.json", "enroll"},
		"-config",
		true,
		"myconfig.json",
		[]string{"fabric-ca", "client", "enroll"})
	testGetCommandLineOptValue(t,
		[]string{"fabric-ca", "client", "-config", "myconfig.json", "enroll"},
		"-config",
		false,
		"myconfig.json",
		[]string{"fabric-ca", "client", "-config", "myconfig.json", "enroll"})
	testGetCommandLineOptValue(t,
		[]string{"fabric-ca", "client", "-config", "myconfig.json", "enroll"},
		"-config2",
		true,
		"",
		[]string{"fabric-ca", "client", "-config", "myconfig.json", "enroll"})
}

func TestSetDefaultServerPort(t *testing.T) {
	testSetDefaultServerPort(t,
		[]string{"fabric-ca", "client", "enroll"},
		[]string{"fabric-ca", "client", "enroll", "-port", "7054"})
	testSetDefaultServerPort(t,
		[]string{"fabric-ca", "client", "enroll", "-port", "1234"},
		[]string{"fabric-ca", "client", "enroll", "-port", "1234"})
}

func TestOpts(t *testing.T) {
	testOpt(t, "-protocol", "protocol", "protocol")
	testOpt(t, "-protocol", "", "http")
	testOpt(t, "-address", "addr", "addr")
	testOpt(t, "-address", "", "localhost")
	testOpt(t, "-port", "port", "port")
	testOpt(t, "-port", "", "7054")
}

func testGetCommandLineOptValue(t *testing.T,
	args []string, opt string, remove bool, expectedVal string, expectedArgs []string) {

	saveArgs := os.Args
	os.Args = args
	val := util.GetCommandLineOptValue(opt, remove)
	if val != expectedVal {
		t.Errorf("val was '%s' but expected '%s'", val, expectedVal)
	}
	compareArgs(t, os.Args, expectedArgs)
	os.Args = saveArgs
}

func testSetDefaultServerPort(t *testing.T, inputArgs []string, expectedOutputArgs []string) {
	saveArgs := os.Args
	os.Args = inputArgs
	util.SetDefaultServerPort()
	compareArgs(t, os.Args, expectedOutputArgs)
	os.Args = saveArgs
}

func testOpt(t *testing.T, opt, val, expectedVal string) {
	saveArgs := os.Args
	if val != "" {
		os.Args = []string{"fabric-ca", "client", "enroll", opt, val}
	} else {
		os.Args = []string{"fabric-ca", "client", "enroll"}
	}
	switch opt {
	case "-protocol":
		val = util.GetServerProtocol()
	case "-address":
		val = util.GetServerAddr()
	case "-port":
		val = util.GetServerPort()
	default:
		panic("bad opt value")
	}
	if val != expectedVal {
		t.Errorf("val was '%s' but expected '%s' for option '%s'", val, expectedVal, opt)
	}
	os.Args = saveArgs
}

func compareArgs(t *testing.T, args, expectedArgs []string) {
	if len(args) == len(expectedArgs) {
		for i, arg := range args {
			if arg != expectedArgs[i] {
				t.Errorf("args were '%+v' but expected '%+v'", args, expectedArgs)
				return
			}
		}
	} else {
		t.Errorf("args were '%+v' but expected '%+v'", args, expectedArgs)
	}

}
