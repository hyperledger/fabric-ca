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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	version = "version"
)

// ServerCmd encapsulates cobra command that provides command line interface
// for the Fabric CA server and the configuration used by the Fabric CA server
type ServerCmd struct {
	// name of the fabric-ca-server command (init, start, version)
	name string
	// rootCmd is the cobra command
	rootCmd *cobra.Command
	// My viper instance
	myViper *viper.Viper
	// blockingStart indicates whether to block after starting the server or not
	blockingStart bool
	// cfgFileName is the name of the configuration file
	cfgFileName string
	// homeDirectory is the location of the server's home directory
	homeDirectory string
	// serverCfg is the server's configuration
	cfg *lib.ServerConfig
}

// NewCommand returns new ServerCmd ready for running
func NewCommand(name string, blockingStart bool) *ServerCmd {
	s := &ServerCmd{
		name:          name,
		blockingStart: blockingStart,
		myViper:       viper.New(),
	}
	s.init()
	return s
}

// Execute runs this ServerCmd
func (s *ServerCmd) Execute() error {
	return s.rootCmd.Execute()
}

// init initializes the ServerCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (s *ServerCmd) init() {
	// root command
	rootCmd := &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := s.configInit()
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			util.CmdRunBegin(s.myViper)
			return nil
		},
	}
	s.rootCmd = rootCmd

	// initCmd represents the server init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: fmt.Sprintf("Initialize the %s", shortName),
		Long:  "Generate the key material needed by the server if it doesn't already exist",
	}
	initCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, initCmd.UsageString())
		}
		err := s.getServer().Init(false)
		if err != nil {
			util.Fatal("Initialization failure: %s", err)
		}
		log.Info("Initialization was successful")
		return nil
	}
	s.rootCmd.AddCommand(initCmd)

	// startCmd represents the server start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Start the %s", shortName),
	}

	startCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, startCmd.UsageString())
		}
		err := s.getServer().Start()
		if err != nil {
			return err
		}
		return nil
	}
	s.rootCmd.AddCommand(startCmd)

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints Fabric CA Server version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(metadata.GetVersionInfo(cmdName))
		},
	}
	s.rootCmd.AddCommand(versionCmd)
	s.registerFlags()
}

// registerFlags registers command flags with viper
func (s *ServerCmd) registerFlags() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	s.myViper.SetEnvPrefix(envVarPrefix)
	s.myViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set specific global flags used by all commands
	pflags := s.rootCmd.PersistentFlags()
	pflags.StringVarP(&s.cfgFileName, "config", "c", "", "Configuration file")
	pflags.MarkHidden("config")
	// Don't want to use the default parameter for StringVarP. Need to be able to identify if home directory was explicitly set
	pflags.StringVarP(&s.homeDirectory, "home", "H", "", fmt.Sprintf("Server's home directory (default \"%s\")", filepath.Dir(cfg)))
	util.FlagString(s.myViper, pflags, "boot", "b", "",
		"The user:pass for bootstrap admin which is required to build default config file")

	// Register flags for all tagged and exported fields in the config
	s.cfg = &lib.ServerConfig{}
	tags := map[string]string{
		"help.csr.cn":           "The common name field of the certificate signing request to a parent fabric-ca-server",
		"help.csr.serialnumber": "The serial number in a certificate signing request to a parent fabric-ca-server",
		"help.csr.hosts":        "A list of comma-separated host names in a certificate signing request to a parent fabric-ca-server",
	}
	err := util.RegisterFlags(s.myViper, pflags, s.cfg, nil)
	if err != nil {
		panic(err)
	}
	caCfg := &lib.CAConfig{}
	err = util.RegisterFlags(s.myViper, pflags, caCfg, tags)
	if err != nil {
		panic(err)
	}
}

// Configuration file is not required for some commands like version
func (s *ServerCmd) configRequired() bool {
	return s.name != version
}

// getServer returns a lib.Server for the init and start commands
func (s *ServerCmd) getServer() *lib.Server {
	return &lib.Server{
		HomeDir:       s.homeDirectory,
		Config:        s.cfg,
		BlockingStart: s.blockingStart,
		CA: lib.CA{
			Config:         &s.cfg.CAcfg,
			ConfigFilePath: s.cfgFileName,
		},
	}
}
