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

package lib

import (
	"github.com/hyperledger/fabric-ca/lib/tls"
)

const (
	// DefaultServerPort is the default listening port for the fabric-ca server
	DefaultServerPort = 7054

	// DefaultServerAddr is the default listening address for the fabric-ca server
	DefaultServerAddr = "0.0.0.0"
)

// ServerConfig is the fabric-ca server's config
// The tags are recognized by the RegisterFlags function in fabric-ca/lib/util.go
// and are as follows:
// "def" - the default value of the field;
// "opt" - the optional one character short name to use on the command line;
// "help" - the help message to display on the command line;
// "skip" - to skip the field.
type ServerConfig struct {
	Port    int    `def:"7054" opt:"p" help:"Listening port of fabric-ca-server"`
	Address string `def:"0.0.0.0" help:"Listening address of fabric-ca-server"`
	Debug   bool   `def:"false" opt:"d" help:"Enable debug level logging"`
	TLS     tls.ServerTLSConfig
	Remote  string `skip:"true"`
	Client  *ClientConfig
	// caCfg is the default CA's config
	CAcfg CAConfig `skip:"true"`
}
