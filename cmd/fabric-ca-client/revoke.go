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
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/spf13/cobra"
)

var errInput = errors.New("Invalid usage; either --revoke.name and/or both --revoke.serial and --revoke.aki are required")

// initCmd represents the init command
var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an identity",
	Long:  "Revoke an identity with fabric-ca server",
	// PreRunE block for this command will check to make sure enrollment
	// information exists before running the command
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf(extraArgsError, args, cmd.UsageString())
		}

		err := configInit(cmd.Name())
		if err != nil {
			return err
		}

		log.Debugf("Client configuration settings: %+v", clientCfg)

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := runRevoke(cmd)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
}

// The client revoke main logic
func runRevoke(cmd *cobra.Command) error {
	log.Debug("Revoke Entered")

	var err error

	client := lib.Client{
		HomeDir: filepath.Dir(cfgFileName),
		Config:  clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	// aki and serial # are required to revoke a certificate. The enrollment ID
	// is required to revoke an identity. So, either aki and serial must be
	// specified OR enrollment ID must be specified, else return an error.
	// Note that all three can be specified, in which case server will revoke
	// certificate associated with the specified aki, serial number.
	if (clientCfg.Revoke.Name == "") && (clientCfg.Revoke.AKI == "" || clientCfg.Revoke.Serial == "") {
		cmd.Usage()
		return errInput
	}

	err = id.Revoke(
		&api.RevocationRequest{
			Name:   clientCfg.Revoke.Name,
			Serial: clientCfg.Revoke.Serial,
			AKI:    clientCfg.Revoke.AKI,
			Reason: clientCfg.Revoke.Reason,
			CAName: clientCfg.CAName,
		})

	if err == nil {
		log.Infof("Revocation was successful")
	}

	return err
}
