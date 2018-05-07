/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"fmt"
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func (c *ClientCmd) newReenrollCommand() *cobra.Command {
	reenrollCmd := &cobra.Command{
		Use:   "reenroll",
		Short: "Reenroll an identity",
		Long:  "Reenroll an identity with Fabric CA server",
		// PreRunE block for this command will check to make sure enrollment
		// information exists before running the command
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
			err := c.runReenroll()
			if err != nil {
				return err
			}

			return nil
		},
	}
	return reenrollCmd
}

// The client reenroll main logic
func (c *ClientCmd) runReenroll() error {
	log.Debug("Entered runReenroll")

	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.ReenrollmentRequest{
		Label:   c.clientCfg.Enrollment.Label,
		Profile: c.clientCfg.Enrollment.Profile,
		CSR:     &c.clientCfg.CSR,
		CAName:  c.clientCfg.CAName,
	}

	resp, err := id.Reenroll(req)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("Failed to reenroll '%s'", id.GetName()))
	}

	err = resp.Identity.Store()
	if err != nil {
		return err
	}

	err = storeCAChain(c.clientCfg, &resp.CAInfo)
	if err != nil {
		return err
	}

	return nil
}
