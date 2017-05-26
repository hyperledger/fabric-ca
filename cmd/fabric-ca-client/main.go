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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// rootCmd is the base command for the Hyerledger Fabric CA client
var rootCmd = &cobra.Command{
	Use:   cmdName,
	Short: longName,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		err := checkAndEnableProfiling()
		if err != nil {
			return err
		}
		util.CmdRunBegin()
		cmd.SilenceUsage = true
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if profileMode != "" && profileInst != nil {
			profileInst.Stop()
		}
		return nil
	},
}

const (
	fabricCAClientProfileMode = "FABRIC_CA_CLIENT_PROFILE_MODE"
	extraArgsError            = "Unrecognized arguments found: %v\n\n%s"
)

var (
	persistentFlags pflag.FlagSet
	profileMode     string
	profileInst     interface {
		Stop()
	}
)

func init() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	viper.SetEnvPrefix(envVarPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	host, err := os.Hostname()
	if err != nil {
		log.Error(err)
	}

	// Set global flags used by all commands
	pflags := rootCmd.PersistentFlags()
	pflags.StringVarP(&cfgFileName, "config", "c", cfg, "Configuration file")
	pflags.StringSliceVarP(
		&cfgAttrs, "id.attrs", "", nil, "A space separated list of attributes of the form <name>=<value> (e.g. foo=foo1 bar=bar1)")
	util.FlagString(pflags, "myhost", "m", host,
		"Hostname to include in the certificate signing request during enrollment")

	clientCfg = &lib.ClientConfig{}
	tags := map[string]string{
		"skip.csr.cn":           "true", // Skip CN on client side as enrollment ID is used as CN
		"help.csr.serialnumber": "The serial number in a certificate signing request, which becomes part of the DN (Distinquished Name)",
		"help.csr.hosts":        "A list of host names in a certificate signing request",
	}
	err = util.RegisterFlags(pflags, clientCfg, tags)
	if err != nil {
		panic(err)
	}
}

// The fabric-ca client main
func main() {
	if err := RunMain(os.Args); err != nil {
		os.Exit(1)
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

// checkAndEnableProfiling checks for the FABRIC_CA_CLIENT_PROFILE_MODE
// env variable, if it is set to "cpu", cpu profiling is enbled;
// if it is set to "heap", heap profiling is enabled
func checkAndEnableProfiling() error {
	profileMode = strings.ToLower(os.Getenv(fabricCAClientProfileMode))
	if profileMode != "" {
		wd, err := os.Getwd()
		if err != nil {
			wd = os.Getenv("HOME")
		}
		opt := profile.ProfilePath(wd)
		switch profileMode {
		case "cpu":
			profileInst = profile.Start(opt, profile.CPUProfile)
		case "heap":
			profileInst = profile.Start(opt, profile.MemProfileRate(2048))
		default:
			msg := fmt.Sprintf("Invalid value for the %s environment variable; found '%s', expecting 'cpu' or 'heap'",
				fabricCAClientProfileMode, profileMode)
			return errors.New(msg)
		}
	}
	return nil
}
