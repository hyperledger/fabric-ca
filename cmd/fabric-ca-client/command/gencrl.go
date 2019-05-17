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
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	// crlsFolder is the MSP folder name where generate CRL will be stored
	crlsFolder = "crls"
	// crlFile is the name of the file used to the generate CRL
	crlFile = "crl.pem"
)

func (c *ClientCmd) newGenCRLCommand() *cobra.Command {
	var genCrlCmd = &cobra.Command{
		Use:   "gencrl",
		Short: "Generate a CRL",
		Long:  "Generate a Certificate Revocation List",
		// PreRunE block for this command will load client configuration
		// before running the command
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
			err := c.runGenCRL()
			if err != nil {
				return err
			}
			return nil
		},
	}
	util.RegisterFlags(c.myViper, genCrlCmd.Flags(), &c.crlParams, nil)
	return genCrlCmd
}

// The client register main logic
func (c *ClientCmd) runGenCRL() error {
	log.Debug("Entered runGenCRL")
	client := lib.Client{
		HomeDir: filepath.Dir(c.cfgFileName),
		Config:  c.clientCfg,
	}
	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}
	var revokedAfter, revokedBefore time.Time
	if c.crlParams.RevokedAfter != "" {
		revokedAfter, err = time.Parse(time.RFC3339, c.crlParams.RevokedAfter)
		if err != nil {
			return errors.Wrap(err, "Invalid 'revokedafter' value")
		}
	}
	if c.crlParams.RevokedBefore != "" {
		revokedBefore, err = time.Parse(time.RFC3339, c.crlParams.RevokedBefore)
		if err != nil {
			return errors.Wrap(err, "Invalid 'revokedbefore' value")
		}
	}
	if !revokedBefore.IsZero() && revokedAfter.After(revokedBefore) {
		return errors.Errorf("Invalid revokedafter value '%s'. It must not be a timestamp greater than revokedbefore value '%s'",
			c.crlParams.RevokedAfter, c.crlParams.RevokedBefore)
	}

	var expireAfter, expireBefore time.Time
	if c.crlParams.ExpireAfter != "" {
		expireAfter, err = time.Parse(time.RFC3339, c.crlParams.ExpireAfter)
		if err != nil {
			return errors.Wrap(err, "Invalid 'expireafter' value")
		}
	}
	if c.crlParams.ExpireBefore != "" {
		expireBefore, err = time.Parse(time.RFC3339, c.crlParams.ExpireBefore)
		if err != nil {
			return errors.Wrap(err, "Invalid 'expirebefore' value")
		}
	}
	if !expireBefore.IsZero() && expireAfter.After(expireBefore) {
		return errors.Errorf("Invalid expireafter value '%s'. It must not be a timestamp greater than expirebefore value '%s'",
			c.crlParams.ExpireAfter, c.crlParams.ExpireBefore)
	}
	req := &api.GenCRLRequest{
		CAName:        c.clientCfg.CAName,
		RevokedAfter:  revokedAfter,
		RevokedBefore: revokedBefore,
		ExpireAfter:   expireAfter,
		ExpireBefore:  expireBefore,
	}
	resp, err := id.GenCRL(req)
	if err != nil {
		return err
	}
	log.Info("Successfully generated the CRL")
	err = storeCRL(c.clientCfg, resp.CRL)
	if err != nil {
		return err
	}
	return nil
}

// Store the CRL
func storeCRL(config *lib.ClientConfig, crl []byte) error {
	dirName := path.Join(config.MSPDir, crlsFolder)
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(dirName, os.ModeDir|0755)
		if mkdirErr != nil {
			return errors.Wrapf(mkdirErr, "Failed to create directory %s", dirName)
		}
	}
	fileName := path.Join(dirName, crlFile)
	err := util.WriteFile(fileName, crl, 0644)
	if err != nil {
		return errors.Wrapf(err, "Failed to write CRL to the file %s", fileName)
	}
	log.Infof("Successfully stored the CRL in the file %s", fileName)
	return nil
}
