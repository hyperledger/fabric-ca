/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"os"
	"testing"
)

func TestGetCommandLineOptValue(t *testing.T) {
	testGetCommandLineOptValue(t,
		[]string{"fabric-ca", "client", "-config", "myconfig.json", "enroll"},
		"-config",
		"myconfig.json",
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
	args []string, opt string, expectedVal string, expectedArgs []string) {

	saveArgs := os.Args
	os.Args = args
	val := getCommandLineOptValue(opt)
	if val != expectedVal {
		t.Errorf("val was '%s' but expected '%s'", val, expectedVal)
	}
	compareArgs(t, os.Args, expectedArgs)
	os.Args = saveArgs
}

func testSetDefaultServerPort(t *testing.T, inputArgs []string, expectedOutputArgs []string) {
	saveArgs := os.Args
	os.Args = inputArgs
	setDefaultServerPort()
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
		val = getServerProtocol()
	case "-address":
		val = getServerAddr()
	case "-port":
		val = GetServerPort()
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
