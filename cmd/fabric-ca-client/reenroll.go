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

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var reenrollCmd = &cobra.Command{
	Use:   "reenroll",
	Short: "Reenroll user",
	Long:  "Reenroll user with fabric-ca server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			cmd.Help()
			return nil
		}

		err := runReenroll()
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(reenrollCmd)
	reenrollFlags := reenrollCmd.Flags()
	reenrollFlags.StringVarP(&csrFile, "csrfile", "f", "", "Certificate Signing Request information (Optional)")

}

// The client reenroll main logic
func runReenroll() error {
	log.Debug("Entered Reenroll")

	client := lib.Client{
		HomeDir: filepath.Dir(cfgFileName),
		Config:  clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.ReenrollmentRequest{}

	newID, err := id.Reenroll(req)
	if err != nil {
		return fmt.Errorf("Failed to store enrollment information: %s", err)
	}

	err = newID.Store()
	if err != nil {
		return err
	}

	log.Infof("Enrollment information was successfully stored in %s and %s",
		client.GetMyKeyFile(), client.GetMyCertFile())

	return nil
}
