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

package command

import (
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func (c *ClientCmd) newGenCsrCommand() *cobra.Command {
	// initCmd represents the init command
	gencsrCmd := &cobra.Command{
		Use:   "gencsr",
		Short: "Generate a CSR",
		Long:  "Generate a Certificate Signing Request for an identity",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.ConfigInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runGenCSR(cmd)
			if err != nil {
				return err
			}
			return nil
		},
	}
	gencsrCmd.Flags().StringVar(&c.csrCommonName, "csr.cn", "", "The common name for the certificate signing request")
	return gencsrCmd
}

// The gencsr main logic
func (c *ClientCmd) runGenCSR(cmd *cobra.Command) error {
	log.Debug("Entered runGenCSR")

	if c.csrCommonName != "" {
		c.clientCfg.CSR.CN = c.csrCommonName
	}

	err := c.clientCfg.GenCSR(filepath.Dir(c.cfgFileName))
	if err != nil {
		return err
	}

	return nil
}
