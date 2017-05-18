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
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

var (
	csrFile string
)

// initCmd represents the init command
var enrollCmd = &cobra.Command{
	Use:   "enroll -u http://user:userpw@serverAddr:serverPort",
	Short: "Enroll an identity",
	Long:  "Enroll identity with fabric-ca server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf(extraArgsError, args, cmd.UsageString())
		}

		err := runEnroll(cmd)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)
}

// The client enroll main logic
func runEnroll(cmd *cobra.Command) error {
	log.Debug("Entered runEnroll")
	_, _, err := util.GetUser()
	if err != nil {
		return err
	}

	err = configInit(cmd.Name())
	if err != nil {
		return err
	}

	resp, err := clientCfg.Enroll(clientCfg.URL, filepath.Dir(cfgFileName))
	if err != nil {
		return err
	}

	ID := resp.Identity

	cfgFile, err := ioutil.ReadFile(cfgFileName)
	if err != nil {
		return err
	}

	cfg := strings.Replace(string(cfgFile), "<<<ENROLLMENT_ID>>>", ID.GetName(), 1)

	err = ioutil.WriteFile(cfgFileName, []byte(cfg), 0644)
	if err != nil {
		return err
	}

	err = ID.Store()
	if err != nil {
		return fmt.Errorf("Failed to store enrollment information: %s", err)
	}

	err = storeCAChain(clientCfg, &resp.ServerInfo)
	if err != nil {
		return err
	}

	return nil
}
