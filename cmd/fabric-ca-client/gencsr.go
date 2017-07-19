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
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var gencsrCmd = &cobra.Command{
	Use:   "gencsr",
	Short: "Generate a CSR",
	Long:  "Generate a Certificate Signing Request for an identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf(extraArgsError, args, cmd.UsageString())
		}

		err := runGenCSR(cmd)
		if err != nil {
			return err
		}

		return nil
	},
}

// csrCommonName is the certificate signing request common name specified via the flag
var csrCommonName string

func init() {
	gencsrCmd.Flags().StringVar(&csrCommonName, "csr.cn", "", "The common name for the certificate signing request")
	rootCmd.AddCommand(gencsrCmd)
}

// The client enroll main logic
func runGenCSR(cmd *cobra.Command) error {
	log.Debug("Entered runGenCSR")

	err := configInit(cmd.Name())
	if err != nil {
		return err
	}

	if csrCommonName != "" {
		clientCfg.CSR.CN = csrCommonName
	}

	err = clientCfg.GenCSR(filepath.Dir(cfgFileName))
	if err != nil {
		return err
	}

	return nil
}
