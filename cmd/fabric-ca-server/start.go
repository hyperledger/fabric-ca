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

	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

// startCmd represents the enroll command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: fmt.Sprintf("Start the %s", shortName),
}

func init() {
	startCmd.RunE = runStart
	rootCmd.AddCommand(startCmd)
	flags := startCmd.Flags()
	util.FlagString(flags, "addr", "a", lib.DefaultServerAddr, "Listening address")
	util.FlagInt(flags, "port", "p", lib.DefaultServerPort, "Listening port")
	registerCommonFlags(flags)
}

// The server start main logic
func runStart(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("Usage: too many arguments.\n%s", startCmd.UsageString())
	}
	err := getServer().Start()
	if err != nil {
		return err
	}
	return nil
}
