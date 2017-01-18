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
	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-ca/api"
)

var enrollUsageText = `fabric-ca client enroll -- Enroll with fabric-ca server

Usage of client enroll command:
    Enroll a client and get an ecert:
       fabric-ca client enroll ID SECRET FABRIC-CA-SERVER-ADDR

Arguments:
        ID:                     Enrollment ID
        SECRET:                 Enrollment secret returned by register
        FABRIC-CA-SERVER-ADDR:  Fabric CA server address
	     CSRJSON:                Certificate Signing Request JSON information (Optional)

Flags:
`

var enrollFlags = []string{}

func enrollMain(args []string, c cli.Config) error {
	log.Debug("Entering cli/client/enrollMain")

	id, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	secret, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	fcaServer, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	req := &api.EnrollmentRequest{
		Name:   id,
		Secret: secret,
	}

	client, err := NewClient(fcaServer)
	if err != nil {
		return err
	}

	// Read the CSR JSON file if provided
	if len(args) > 0 {
		path, _, err2 := cli.PopFirstArgument(args)
		if err2 != nil {
			return err2
		}
		req.CSR, err2 = client.LoadCSRInfo(path)
		if err2 != nil {
			return err2
		}
	}

	ID, err := client.Enroll(req)
	if err != nil {
		return err
	}

	err = ID.Store()
	if err != nil {
		return fmt.Errorf("failed to store enrollment information: %s", err)
	}

	log.Infof("enrollment information was successfully stored in %s and %s",
		client.GetMyKeyFile(), client.GetMyCertFile())

	return nil
}

// EnrollCommand is the enroll command
var EnrollCommand = &cli.Command{UsageText: enrollUsageText, Flags: enrollFlags, Main: enrollMain}
