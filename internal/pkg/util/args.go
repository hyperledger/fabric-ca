/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"os"
)

const (
	defaultServerProtocol = "http"
	defaultServerAddr     = "localhost"
	defaultServerPort     = "7054"
)

// GetServerURL returns the server's URL
func GetServerURL() string {
	return fmt.Sprintf("%s://%s:%s", getServerProtocol(), getServerAddr(), GetServerPort())
}

// GetServerPort returns the server's listening port
func GetServerPort() string {
	port := getCommandLineOptValue("-port")
	if port != "" {
		return port
	}
	return defaultServerPort
}

// getCommandLineOptValue searches the command line arguments for the
// specified option and returns the following value if found; otherwise
// it returns "".
// For example, if command line is:
//    fabric-ca client enroll -config myconfig.json
// getCommandLineOptValue("-config") returns "myconfig.json"
func getCommandLineOptValue(optName string) string {
	for i := 0; i < len(os.Args)-1; i++ {
		if os.Args[i] == optName {
			val := os.Args[i+1]
			return val
		}
	}
	return ""
}

// getServerProtocol returns the server's protocol
func getServerProtocol() string {
	protocol := getCommandLineOptValue("-protocol")
	if protocol != "" {
		return protocol
	}
	return defaultServerProtocol
}

// getServerAddr returns the server's address
func getServerAddr() string {
	addr := getCommandLineOptValue("-address")
	if addr != "" {
		return addr
	}
	return defaultServerAddr
}

// setDefaultServerPort overrides the default CFSSL server port
// by adding the "-port" option to the command line if it was not
// already present.
func setDefaultServerPort() {
	if len(os.Args) > 2 && getCommandLineOptValue("-port") == "" {
		os.Args = append(os.Args, "-port", defaultServerPort)
	}
}
