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

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type identityArgs struct {
	id     string
	json   string
	add    api.AddIdentityRequest
	modify api.ModifyIdentityRequest
	remove api.RemoveIdentityRequest
}

func (c *ClientCmd) newIdentityCommand() *cobra.Command {
	identityCmd := &cobra.Command{
		Use:   "identity",
		Short: "Update an identity",
		Long:  "Dynamically update an identity on Fabric CA server",
	}
	identityCmd.AddCommand(c.newListIdentityCommand())
	identityCmd.AddCommand(c.newAddIdentityCommand())
	identityCmd.AddCommand(c.newModifyIdentityCommand())
	identityCmd.AddCommand(c.newRemoveIdentityCommand())
	return identityCmd
}

func (c *ClientCmd) newListIdentityCommand() *cobra.Command {
	identityListCmd := &cobra.Command{
		Use:   "list",
		Short: "List information an identity or identities",
		Long:  "List information an identity or identities from the Fabric CA server",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runListIdentity()
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityListCmd.Flags()
	flags.StringVarP(
		&c.dynamicIdentity.id, "id", "", "", "Get identity information from the fabric-ca server")
	return identityListCmd
}

func (c *ClientCmd) newAddIdentityCommand() *cobra.Command {
	identityAddCmd := &cobra.Command{
		Use:     "add",
		Short:   "Add identity",
		Long:    "Add an identity on Fabric CA server",
		Example: "fabric-ca-client identity add <id> [flags]\nfabric-ca-client identity add user1 --type peer",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args)
			if err != nil {
				return err
			}

			err = c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runAddIdentity(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityAddCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.add.IdentityInfo, nil)
	flags.StringVarP(
		&c.dynamicIdentity.add.Secret, "secret", "", "", "The enrollment secret for the identity being registered")
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for adding a new identity")
	return identityAddCmd
}

func (c *ClientCmd) newModifyIdentityCommand() *cobra.Command {
	identityModifyCmd := &cobra.Command{
		Use:     "modify",
		Short:   "Modify identity",
		Long:    "Modify an existing identity on Fabric CA server",
		Example: "fabric-ca-client identity modify <id> [flags]\nfabric-ca-client identity modify user1 --type peer",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args)
			if err != nil {
				return err
			}

			err = c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runModifyIdentity(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	flags := identityModifyCmd.Flags()
	tags := map[string]string{
		"skip.id": "true",
	}
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.modify.IdentityInfo, tags)
	flags.StringVarP(
		&c.dynamicIdentity.modify.Secret, "secret", "", "", "The enrollment secret for the identity being registered")
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for modifying an existing identity")
	return identityModifyCmd
}

func (c *ClientCmd) newRemoveIdentityCommand() *cobra.Command {
	identityRemoveCmd := &cobra.Command{
		Use:     "remove",
		Short:   "Remove identity",
		Long:    "Remove an identity from Fabric CA server",
		Example: "fabric-ca-client identity remove <id> [flags]\nfabric-ca-client identity remove user1",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			err := argsCheck(args)
			if err != nil {
				return err
			}

			err = c.configInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.runRemoveIdentity(args)
			if err != nil {
				return err
			}

			return nil
		},
	}
	return identityRemoveCmd
}

// The client side logic for executing list identity command
func (c *ClientCmd) runListIdentity() error {
	log.Debug("Entered runListIdentity")

	id, err := c.loadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.id != "" {
		resp, err := id.GetIdentity(c.dynamicIdentity.id, c.clientCfg.CAName)
		if err != nil {
			return err
		}

		fmt.Printf("Identity: %+v\n", resp.IdentityInfo)
		return nil
	}

	resp, err := id.GetAllIdentities(c.clientCfg.CAName)
	if err != nil {
		return err
	}

	fmt.Println("Identities:")
	for _, id := range resp.Identities {
		fmt.Printf("%+v\n", id)
	}

	return nil
}

// The client side logic for adding an identity
func (c *ClientCmd) runAddIdentity(args []string) error {
	log.Debug("Entered runAddIdentity")

	// TODO

	return errors.Errorf("Not Implemented")
}

// The client side logic for modifying an identity
func (c *ClientCmd) runModifyIdentity(args []string) error {
	log.Debug("Entered runModifyIdentity")

	// TODO

	return errors.Errorf("Not Implemented")
}

// The client side logic for removing an identity
func (c *ClientCmd) runRemoveIdentity(args []string) error {
	log.Debug("Entered runRemoveIdentity")

	// TODO

	return errors.Errorf("Not Implemented")
}

func argsCheck(args []string) error {
	if len(args) == 0 {
		return errors.Errorf("Identity name is required")
	}
	if len(args) > 1 {
		return errors.Errorf("Too many arguments, only the identity name should be passed in as argument")
	}
	return nil
}
