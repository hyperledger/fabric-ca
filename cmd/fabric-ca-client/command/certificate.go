/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	calog "github.com/hyperledger/fabric-ca/lib/common/log"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type certificateCommand struct {
	command  Command
	list     api.GetCertificatesRequest
	timeArgs timeArgs
	store    string
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
	flags.StringVarP(&c.store, "store", "", "", "Store requested certificates in this location")
	viper := c.command.GetViper()
	util.RegisterFlags(viper, flags, &c.list, nil)
	util.RegisterFlags(viper, flags, &c.timeArgs, nil)
	return certificateListCmd
}

func (c *certificateCommand) preRunCertificate(cmd *cobra.Command, args []string) error {
	c.command.SetDefaultLogLevel(calog.WARNING)
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

	err = c.getCertListReq()
	if err != nil {
		return err
	}

	req := &c.list
	req.CAName = c.command.GetClientCfg().CAName

	if c.store != "" {
		if !filepath.IsAbs(c.store) {
			c.store = filepath.Join(c.command.GetHomeDirectory(), c.store)
		}
		log.Infof("Certificates stored at: %s", c.store)
	}

	certDecoder := lib.NewCertificateDecoder(c.store)
	return id.GetCertificates(req, certDecoder.CertificateDecoder)
}

func (c *certificateCommand) getCertListReq() error {
	log.Debug("Parse expiration/revocation time range and generate certificate list request")
	listReq := &c.list
	expirationRange := c.timeArgs.Expiration
	revocationRange := c.timeArgs.Revocation

	if expirationRange != "" {
		timeArgs, err := parseTimeRange(expirationRange, "expiration")
		if err != nil {
			return err
		}
		listReq.Expired.StartTime = getTime(timeArgs[0])
		listReq.Expired.EndTime = getTime(timeArgs[1])
	}

	if revocationRange != "" {
		timeArgs, err := parseTimeRange(revocationRange, "revocation")
		if err != nil {
			return err
		}
		listReq.Revoked.StartTime = getTime(timeArgs[0])
		listReq.Revoked.EndTime = getTime(timeArgs[1])
	}

	return nil
}

func parseTimeRange(str, name string) ([]string, error) {
	log.Debugf("Parsing %s time range: %s", name, str)
	if !strings.Contains(str, "::") {
		return nil, errors.Errorf("Invalid %s format, expecting '<start>::<end>' but found %s, missing '::' sepatator", name, str)
	}

	timeArgs := strings.Split(str, "::")
	for _, timeArg := range timeArgs {
		if strings.Contains(timeArg, "/") {
			return nil, errors.Errorf("Invalid %s format, use '-' instead of '/' in time format: %s", name, str)
		}
	}

	return timeArgs, nil
}

func getTime(timeArg string) string {
	if strings.ToLower(timeArg) == "now" {
		currentTime := time.Now().UTC()
		return currentTime.Format(time.RFC3339)
	}
	return timeArg
}
