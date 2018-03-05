/*
Copyright IBM Corp. 2017, 2018 All Rights Reserved.

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
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/spf13/cobra"
)

type certificateCommand struct {
	command  Command
	list     api.GetCertificatesRequest
	timeArgs timeArgs
}

type timeArgs struct {
	// Get certificates that were revoked between the UTC timestamp (RFC3339 format) or duration specified
	Revocation string `help:"Get certificates that were revoked between the UTC timestamp (RFC3339 format) or duration specified (e.g. <begin_time>::<end_time>)"`
	// Get certificates which expire between the UTC timestamp (RFC3339 format) or duration specified
	Expiration string `help:"Get certificates which expire between the UTC timestamp (RFC3339 format) or duration specified (e.g. <begin_time>::<end_time>)"`
}

// createCertificateCommand will create the certificate cobra command
func createCertificateCommand(clientCmd Command) *cobra.Command {
	return addCertificateCommand(newCertificateCommand(clientCmd))
}

func newCertificateCommand(clientCmd Command) *certificateCommand {
	return &certificateCommand{
		command: clientCmd,
	}
}

func addCertificateCommand(c *certificateCommand) *cobra.Command {
	certificateCmd := &cobra.Command{
		Use:   "certificate",
		Short: "Manage certificates",
		Long:  "Manage certificates",
	}
	certificateCmd.AddCommand(newListCertificateCommand(c))
	return certificateCmd
}

func newListCertificateCommand(c *certificateCommand) *cobra.Command {
	certificateListCmd := &cobra.Command{
		Use:     "list",
		Short:   "List certificates",
		Long:    "List all certificates which are visible to the caller and match the flags",
		Example: "fabric-ca-client certificate list --id admin --expiration 2018-01-01::2018-01-30\nfabric-ca-client certificate list --id admin --expiration 2018-01-01T01:30:00z::2018-01-30T11:30:00z\nfabric-ca-client certificate list --id admin --expiration -30d::-15d",
		PreRunE: c.preRunCertificate,
		RunE:    c.runListCertificate,
	}
	flags := certificateListCmd.Flags()
	flags.StringVarP(&c.list.ID, "id", "", "", "Get certificates for this enrollment ID")
	viper := c.command.GetViper()
	util.RegisterFlags(viper, flags, &c.list, nil)
	util.RegisterFlags(viper, flags, &c.timeArgs, nil)
	return certificateListCmd
}

func (c *certificateCommand) preRunCertificate(cmd *cobra.Command, args []string) error {
	log.Level = log.LevelWarning
	err := c.command.ConfigInit()
	if err != nil {
		return err
	}

	log.Debugf("Client configuration settings: %+v", c.command.GetClientCfg())

	return nil
}

// The client side logic for executing list certificates command
func (c *certificateCommand) runListCertificate(cmd *cobra.Command, args []string) error {
	log.Debug("Entered runListCertificate")

	id, err := c.command.LoadMyIdentity()
	if err != nil {
		return err
	}

	req := &c.list
	req.CAName = c.command.GetClientCfg().CAName

	return id.GetCertificates(req, nil)
}
