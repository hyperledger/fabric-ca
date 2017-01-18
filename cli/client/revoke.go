/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package client

import (
	"fmt"

	"github.com/cloudflare/cfssl/cli"
	"github.com/hyperledger/fabric-ca/api"
)

var revokeUsageTxt = `fabric-ca client revoke -- revokes one or more certificates

Usage:

Revoke certificate(s):
	   fabric-ca client revoke FABRIC-CA-SERVER-URL [ENROLLMENT-ID]

Arguments:
     FABRIC-CA-SERVER-URL:     The URL of the fabric-ca server
     ENROLLMENT_ID:            Optional enrollment ID

Flags:
`

var revokeFlags = []string{"aki", "serial", "reason"}

func revokeMain(args []string, c cli.Config) error {

	fcaServer, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	var enrollmentID string
	if len(args) > 0 {
		enrollmentID, _, err = cli.PopFirstArgument(args)
		if err != nil {
			return err
		}
	}

	client, err := NewClient(fcaServer)
	if err != nil {
		return err
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return err
	}

	if enrollmentID == "" && c.Serial == "" {
		return fmt.Errorf("Invalid usage; either ENROLLMENT_ID or both -serial and -aki are required")
	}

	return id.Revoke(
		&api.RevocationRequest{
			Name:   enrollmentID,
			Serial: c.Serial,
			AKI:    c.AKI,
		})
}

// RevokeCommand assembles the definition of Command 'revoke'
var RevokeCommand = &cli.Command{
	UsageText: revokeUsageTxt,
	Flags:     revokeFlags,
	Main:      revokeMain,
}
