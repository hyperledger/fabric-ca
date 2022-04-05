/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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

func testGetCommandLineOptValue(t *testing.T, args []string, opt string, expectedVal string, expectedArgs []string) {
	defer func(args []string) { os.Args = args }(os.Args)

	os.Args = args
	val := getCommandLineOptValue(opt)
	assert.Equal(t, expectedVal, val)
	assert.Equal(t, expectedArgs, os.Args)
}

func testSetDefaultServerPort(t *testing.T, inputArgs []string, expectedOutputArgs []string) {
	defer func(args []string) { os.Args = args }(os.Args)

	os.Args = inputArgs
	setDefaultServerPort()
	assert.Equal(t, expectedOutputArgs, os.Args)
}

func testOpt(t *testing.T, opt, val, expectedVal string) {
	defer func(args []string) { os.Args = args }(os.Args)

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
	assert.Equal(t, expectedVal, val, "unexpected value for option '%s'", opt)
}
