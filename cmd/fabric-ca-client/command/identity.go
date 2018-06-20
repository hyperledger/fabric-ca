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
	"fmt"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	calog "github.com/hyperledger/fabric-ca/lib/common/log"
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
		Short: "Manage identities",
		Long:  "Manage identities",
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
		Short: "List identities",
		Long:  "List identities visible to caller",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			c.SetDefaultLogLevel(calog.WARNING)
			err := c.ConfigInit()
			if err != nil {
				return err
			}

			log.Debugf("Client configuration settings: %+v", c.clientCfg)

			return nil
		},
		RunE: c.runListIdentity,
	}
	flags := identityListCmd.Flags()
	flags.StringVarP(
		&c.dynamicIdentity.id, "id", "", "", "Get identity information from the fabric-ca server")
	return identityListCmd
}

func (c *ClientCmd) newAddIdentityCommand() *cobra.Command {
	identityAddCmd := &cobra.Command{
		Use:     "add <id>",
		Short:   "Add identity",
		Long:    "Add an identity",
		Example: "fabric-ca-client identity add user1 --type peer",
		PreRunE: c.identityPreRunE,
		RunE:    c.runAddIdentity,
	}
	flags := identityAddCmd.Flags()
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.add, nil)
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for adding a new identity")
	return identityAddCmd
}

func (c *ClientCmd) newModifyIdentityCommand() *cobra.Command {
	identityModifyCmd := &cobra.Command{
		Use:     "modify <id>",
		Short:   "Modify identity",
		Long:    "Modify an existing identity",
		Example: "fabric-ca-client identity modify user1 --type peer",
		PreRunE: c.identityPreRunE,
		RunE:    c.runModifyIdentity,
	}
	flags := identityModifyCmd.Flags()
	tags := map[string]string{
		"skip.id": "true",
	}
	util.RegisterFlags(c.myViper, flags, &c.dynamicIdentity.modify, tags)
	flags.StringSliceVarP(
		&c.cfgAttrs, "attrs", "", nil, "A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)")
	flags.StringVarP(
		&c.dynamicIdentity.json, "json", "", "", "JSON string for modifying an existing identity")
	return identityModifyCmd
}

func (c *ClientCmd) newRemoveIdentityCommand() *cobra.Command {
	identityRemoveCmd := &cobra.Command{
		Use:     "remove <id>",
		Short:   "Remove identity",
		Long:    "Remove an identity",
		Example: "fabric-ca-client identity remove user1",
		PreRunE: c.identityPreRunE,
		RunE:    c.runRemoveIdentity,
	}
	flags := identityRemoveCmd.Flags()
	flags.BoolVarP(
		&c.dynamicIdentity.remove.Force, "force", "", false, "Forces removing your own identity")
	return identityRemoveCmd
}

// The client side logic for executing list identity command
func (c *ClientCmd) runListIdentity(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runListIdentity")

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.id != "" {
		resp, err := id.GetIdentity(c.dynamicIdentity.id, c.clientCfg.CAName)
		if err != nil {
			return err
		}

		fmt.Printf("Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Attributes)
		return nil
	}

	err = id.GetAllIdentities(c.clientCfg.CAName, lib.IdentityDecoder)
	if err != nil {
		return err
	}

	return nil
}

// The client side logic for adding an identity
func (c *ClientCmd) runAddIdentity(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runAddIdentity: %+v", c.dynamicIdentity)
	if c.dynamicIdentity.json != "" && checkOtherFlags(cmd) {
		return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
	}

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &api.AddIdentityRequest{}

	if c.dynamicIdentity.json != "" {
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), &req, "addIdentity")
		if err != nil {
			return errors.Wrap(err, "Invalid value for --json option")
		}
	} else {
		req = &c.dynamicIdentity.add
		req.Attributes = c.clientCfg.ID.Attributes
	}

	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.AddIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added identity - Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Secret: %s, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Secret, resp.Attributes)
	return nil
}

// The client side logic for modifying an identity
func (c *ClientCmd) runModifyIdentity(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runModifyIdentity: %+v", c.dynamicIdentity)
	if c.dynamicIdentity.json != "" && checkOtherFlags(cmd) {
		return errors.Errorf("Can't use 'json' flag in conjunction with other flags")
	}

	req := &api.ModifyIdentityRequest{}

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	if c.dynamicIdentity.json != "" {
		err := util.Unmarshal([]byte(c.dynamicIdentity.json), req, "modifyIdentity")
		if err != nil {
			return errors.Wrap(err, "Invalid value for --json option")
		}
	} else {
		req = &c.dynamicIdentity.modify
		req.Attributes = c.clientCfg.ID.Attributes
	}

	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.ModifyIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully modified identity - Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Secret: %s, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Secret, resp.Attributes)
	return nil
}

// The client side logic for removing an identity
func (c *ClientCmd) runRemoveIdentity(cmd *cobra.Command, args []string) error {
	log.Debugf("Entered runRemoveIdentity: %+v", c.dynamicIdentity)

	id, err := c.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &c.dynamicIdentity.remove
	req.ID = args[0]
	req.CAName = c.clientCfg.CAName
	resp, err := id.RemoveIdentity(req)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed identity - Name: %s, Type: %s, Affiliation: %s, Max Enrollments: %d, Attributes: %+v\n", resp.ID, resp.Type, resp.Affiliation, resp.MaxEnrollments, resp.Attributes)
	return nil
}

func (c *ClientCmd) identityPreRunE(cmd *cobra.Command, args []string) error {
	err := argsCheck(args, "Identity")
	if err != nil {
		return err
	}

	err = c.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.clientCfg)

	return nil
}

// checkOtherFlags returns true if other flags besides '--json' are set
// Viper.IsSet does not work correctly if there are defaults defined for
// flags. This is a workaround until this bug is addressed in Viper.
// Viper Bug: https://github.com/spf13/viper/issues/276
func checkOtherFlags(cmd *cobra.Command) bool {
	checkFlags := []string{"id", "type", "affiliation", "secret", "maxenrollments", "attrs"}
	flags := cmd.Flags()
	for _, checkFlag := range checkFlags {
		flag := flags.Lookup(checkFlag)
		if flag != nil {
			if flag.Changed {
				return true
			}
		}
	}

	return false
}

func argsCheck(args []string, field string) error {
	if len(args) == 0 {
		return errors.Errorf("%s name is required", field)
	}
	if len(args) > 1 {
		return errors.Errorf("Unknown argument '%s', only the identity name should be passed in as non-flag argument", args[1])
	}
	return nil
}
