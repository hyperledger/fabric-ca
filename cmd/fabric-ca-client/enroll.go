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
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
)

func (c *ClientCmd) newEnrollCommand() *cobra.Command {
	enrollCmd := &cobra.Command{
		Use:   "enroll -u http://user:userpw@serverAddr:serverPort",
		Short: "Enroll an identity",
		Long:  "Enroll identity with Fabric CA server",
		// PreRunE block for this command will check to make sure username
		// and secret provided for the enroll command before creating and/or
		// reading configuration file
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
			err := c.runEnroll(cmd)
			if err != nil {
				return err
			}
			return nil
		},
	}
	return enrollCmd
}

// The client enroll main logic
func (c *ClientCmd) runEnroll(cmd *cobra.Command) error {
	log.Debug("Entered runEnroll")
	resp, err := c.clientCfg.Enroll(c.clientCfg.URL, filepath.Dir(c.cfgFileName))
	if err != nil {
		return err
	}

	ID := resp.Identity

	cfgFile, err := ioutil.ReadFile(c.cfgFileName)
	if err != nil {
		return errors.Wrapf(err, "Failed to read file at '%s'", c.cfgFileName)
	}

	cfg := strings.Replace(string(cfgFile), "<<<ENROLLMENT_ID>>>", ID.GetName(), 1)

	err = ioutil.WriteFile(c.cfgFileName, []byte(cfg), 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write file at '%s'", c.cfgFileName)
	}

	err = ID.Store()
	if err != nil {
		return errors.WithMessage(err, "Failed to store enrollment information")
	}

	err = storeCAChain(c.clientCfg, &resp.ServerInfo)
	if err != nil {
		return err
	}

	return nil
}
