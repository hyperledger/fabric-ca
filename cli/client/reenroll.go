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

	"github.com/hyperledger/fabric-cop/idp"
)

var reenrollUsageText = `cop client reenroll -- Reenroll with COP server

Usage of client enroll command:
   cop client reenroll COP-SERVER-ADDR

Arguments:
        COP-SERVER-ADDR:  COP server address
		  CSRJSON:          Certificate Signing Request JSON information (Optional)

Flags:
`

var reenrollFlags = []string{}

func reenrollMain(args []string, c cli.Config) error {
	log.Debug("Entering cli/client/reenrollMain")

	copServer, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	client, err := NewClient(copServer)
	if err != nil {
		return err
	}

	id, err := client.LoadMyIdentity()
	if err != nil {
		return fmt.Errorf("Client is not yet enrolled: %s", err)
	}

	req := &idp.ReenrollmentRequest{ID: id}

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

	newID, err := client.Reenroll(req)
	if err != nil {
		return fmt.Errorf("failed to store enrollment information: %s", err)
	}

	err = newID.Store()
	if err != nil {
		return err
	}

	log.Infof("enrollment information was successfully stored in %s and %s",
		client.GetMyKeyFile(), client.GetMyCertFile())

	return nil
}

// ReenrollCommand is the enroll command
var ReenrollCommand = &cli.Command{UsageText: reenrollUsageText, Flags: reenrollFlags, Main: reenrollMain}
