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
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type signingCertArgs struct {
	name string
}

func (c *ClientCmd) newSigningCertCommand() *cobra.Command {
	signingCertCmd := &cobra.Command{
		Use:   "signingcert --signingcert.name <name> ",
		Short: "Get Signing Cert for an identity",
		Long:  "Get Signing Cert for an identity with Fabric CA server",
		// PreRunE block for this command will check to make sure enrollment
		// information exists before running the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.Errorf(extraArgsError, args, cmd.UsageString())
			}

			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runSigningCert()
			if err != nil {
				return err
			}

			return nil
		},
	}
	return signingCertCmd
}

// The client Signing Cert main logic
func (c *ClientCmd) runSigningCert() error {
	log.Debug("Entered runSigningCert")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	resp, err := id.SigningCert(&c.clientCfg.SigningCert)
	if err != nil {
		return err
	}
	file := "signcert.pem"
	cert := []byte(resp.Cert)
	util.WriteFile(file, cert, 0644)

	fmt.Printf("Wrote Signing Cert to %s:\n", file)

	return nil
}
