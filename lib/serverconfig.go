/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/hyperledger/fabric-ca/lib/server/operations"
	"github.com/hyperledger/fabric-ca/lib/tls"
)

const (
	// DefaultServerPort is the default listening port for the fabric-ca server
	DefaultServerPort = 7054

	// DefaultServerAddr is the default listening address for the fabric-ca server
	DefaultServerAddr = "0.0.0.0"
)

// ServerConfig is the fabric-ca server's config
// The tags are recognized by the RegisterFlags function in fabric-ca/util/flag.go
// and are as follows:
// "def" - the default value of the field;
// "opt" - the optional one character short name to use on the command line;
// "help" - the help message to display on the command line;
// "skip" - to skip the field.
type ServerConfig struct {
	// Listening port for the server
	Port int `def:"7054" opt:"p" help:"Listening port of fabric-ca-server"`
	// Bind address for the server
	Address string `def:"0.0.0.0" help:"Listening address of fabric-ca-server"`
	// Cross-Origin Resource Sharing settings for the server
	CORS CORS
	// Enables debug logging
	Debug bool `def:"false" opt:"d" help:"Enable debug level logging" hide:"true"`
	// Sets the logging level on the server
	LogLevel string `help:"Set logging level (info, warning, debug, error, fatal, critical)"`
	// TLS for the server's listening endpoint
	TLS tls.ServerTLSConfig
	// Optional client config for an intermediate server which acts as a client
	// of the root (or parent) server
	Client *ClientConfig `skip:"true"`
	// CACfg is the default CA's config
	CAcfg CAConfig `skip:"true"`
	// The names of the CA configuration files
	// This is empty unless there are non-default CAs served by this server
	CAfiles []string `help:"A list of comma-separated CA configuration files"`
	// The number of non-default CAs, which is useful for a dev environment to
	// quickly start any number of CAs in a single server
	CAcount int `def:"0" help:"Number of non-default CA instances"`
	// Size limit of an acceptable CRL in bytes
	CRLSizeLimit int `def:"512000" help:"Size limit of an acceptable CRL in bytes"`
	// CompMode1_3 determines if to run in comptability for version 1.3
	CompMode1_3 bool `skip:"true"`
	// Metrics contains the configuration for provider and statsd
	Metrics operations.MetricsOptions `hide:"true"`
	// Operations contains the configuration for the operations servers
	Operations operations.Options `hide:"true"`
}

// CORS defines the Cross-Origin Resource Sharing settings for the server.
type CORS struct {
	Enabled bool     `help:"Enable CORS for the fabric-ca-server"`
	Origins []string `help:"Comma-separated list of Access-Control-Allow-Origin domains"`
}
