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
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

var (
	csrFile string
)

// initCmd represents the init command
var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll user",
	Long:  "Enroll user with fabric-ca server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			cmd.Help()
			return nil
		}

		err := runEnroll()
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)
	enrollFlags := enrollCmd.Flags()
	util.FlagString(enrollFlags, "user", "u", "", "user:pass for user being enrolled")
}

// The client enroll main logic
func runEnroll() error {
	log.Debug("Entered Enroll")

	user, pass, err := util.GetUser()
	if err != nil {
		return err
	}

	req := &api.EnrollmentRequest{
		Name:   user,
		Secret: pass,
	}

	_ = req

	log.Infof("User Enrolled")

	return nil
}
