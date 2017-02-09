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
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// rootCmd is the base command for the Hyerledger Fabric CA client
var rootCmd = &cobra.Command{
	Use:   cmdName,
	Short: longName,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		err := configInit()
		if err != nil {
			return err
		}

		util.CmdRunBegin()
		return nil
	},
}

var (
	persistentFlags pflag.FlagSet
)

func init() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	viper.SetEnvPrefix(envVarPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	url := util.GetServerURL()

	host, err := os.Hostname()
	if err != nil {
		log.Error(err)
	}

	// Set global flags used by all commands
	pflags := rootCmd.PersistentFlags()
	pflags.StringVarP(&cfgFileName, "config", "c", cfg, "Configuration file")
	util.FlagString(pflags, "url", "u", url, "URL of the Fabric-ca server")
	util.FlagString(pflags, "myhost", "m", host,
		"Hostname to include in the certificate signing request during enrollment")
	util.FlagBool(pflags, "debug", "d", false, "Enable debug logging")

}

// The fabric-ca client main
func main() {
	if err := RunMain(os.Args); err != nil {
		util.Fatal("%s", err)
	}
}

// RunMain is the fabric-ca client main
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
