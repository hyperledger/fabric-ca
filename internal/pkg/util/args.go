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
