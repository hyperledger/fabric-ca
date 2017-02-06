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
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// initCmd represents the init command
var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke user",
	Long:  "Revoke user with fabric-ca server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			cmd.Help()
			return nil
		}

		err := runRevoke()
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
	revokeFlags := revokeCmd.Flags()
	util.FlagString(revokeFlags, "userid", "u", "", "Enrollment ID (Optional)")
}

// The client revoke main logic
func runRevoke() error {
	log.Debug("Entered Revoke")

	enrollmentID := viper.GetString("userid")
	_ = enrollmentID

	log.Infof("User Revoked")

	return nil
}
