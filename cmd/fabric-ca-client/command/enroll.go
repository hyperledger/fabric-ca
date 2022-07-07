/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type enrollCmd struct {
	Command
}

func newEnrollCmd(c Command) *enrollCmd {
	enrollCmd := &enrollCmd{c}
	return enrollCmd
}

func (c *enrollCmd) getCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "enroll -u http://user:userpw@serverAddr:serverPort",
		Short:   "Enroll an identity",
		Long:    "Enroll identity with Fabric CA server",
		PreRunE: c.preRunEnroll,
		RunE:    c.runEnroll,
	}
	return cmd
}

func (c *enrollCmd) preRunEnroll(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errors.Errorf(extraArgsError, args, cmd.UsageString())
	}

	err := c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.GetClientCfg())

	return nil
}

func (c *enrollCmd) runEnroll(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runEnroll")
	cfgFileName := c.GetCfgFileName()
	cfg := c.GetClientCfg()
	resp, err := cfg.Enroll(cfg.URL, filepath.Dir(cfgFileName))
	if err != nil {
		return err
	}

	ID := resp.Identity

	cfgFile, err := ioutil.ReadFile(cfgFileName)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file at '%s'", cfgFileName)
	}

	cfgStr := strings.Replace(string(cfgFile), "<<<ENROLLMENT_ID>>>", ID.GetName(), 1)

	err = ioutil.WriteFile(cfgFileName, []byte(cfgStr), 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write file at '%s'", cfgFileName)
	}

	err = ID.Store()
	if err != nil {
		return errors.WithMessage(err, "Failed to store enrollment information")
	}

	// Store issuer public key
	err = storeCAChain(cfg, &resp.CAInfo)
	if err != nil {
		return err
	}
	err = storeIssuerPublicKey(cfg, &resp.CAInfo)
	if err != nil {
		return err
	}
	return storeIssuerRevocationPublicKey(cfg, &resp.CAInfo)
}
