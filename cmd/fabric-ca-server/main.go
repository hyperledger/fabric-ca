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
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd is the base command for the Hyerledger Fabric CA server
var (
	rootCmd = &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := configInit()
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			util.CmdRunBegin()
			return nil
		},
	}
	blockingStart = true
)

func init() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	viper.SetEnvPrefix(envVarPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set specific global flags used by all commands
	pflags := rootCmd.PersistentFlags()
	pflags.StringVarP(&cfgFileName, "config", "c", cfg, "Configuration file")
	util.FlagString(pflags, "boot", "b", "",
		"The user:pass for bootstrap admin which is required to build default config file")

	// Register flags for all tagged and exported fields in the config
	serverCfg = &lib.ServerConfig{}
	tags := map[string]string{
		"help.csr.cn":           "The common name field of the certificate signing request to a parent fabric-ca-server",
		"skip.csr.serialnumber": "true",
		"help.csr.hosts":        "A list of space-separated host names in a certificate signing request to a parent fabric-ca-server",
	}
	err := util.RegisterFlags(pflags, serverCfg, nil)
	if err != nil {
		panic(err)
	}
	caCfg := &lib.CAConfig{}
	err = util.RegisterFlags(pflags, caCfg, tags)
	if err != nil {
		panic(err)
	}
}

// The fabric-ca server main
func main() {
	if err := RunMain(os.Args); err != nil {
		os.Exit(1)
	}
}

// RunMain is the fabric-ca server main
func RunMain(args []string) error {

	// Save the os.Args
	saveOsArgs := os.Args
	os.Args = args

	// Execute the command
	err := rootCmd.Execute()

	// Restore original os.Args
	os.Args = saveOsArgs

	return err
}

// Get a server for the init and start commands
func getServer() *lib.Server {
	return &lib.Server{
		HomeDir:       filepath.Dir(cfgFileName),
		Config:        serverCfg,
		BlockingStart: blockingStart,
		CA: lib.CA{
			Config: &serverCfg.CAcfg,
		},
	}
}
