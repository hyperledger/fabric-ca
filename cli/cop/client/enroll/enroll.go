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

package enroll

import (
	"fmt"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	cutil "github.com/hyperledger/fabric-cop/cli/cop/client"
	"github.com/hyperledger/fabric-cop/cli/cop/config"
	"github.com/hyperledger/fabric-cop/idp"
)

var usageText = `cop client enroll -- Enroll with COP server

Usage of client enroll command:
    Enroll a client and get an ecert:
        cop client enroll ID SECRET COP-SERVER-ADDR

Arguments:
        ID:               Enrollment ID
        SECRET:           Enrollment secret returned by register
        CSRJSON:          Certificate Signing Request JSON information
        COP-SERVER-ADDR:  COP server address

Flags:
`

var flags = []string{}

func myMain(args []string, c cli.Config) error {
	fmt.Println("enroll - main()")

	config.Init(&c)

	log.Debug("in myMain of 'cop client enroll'")

	id, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	secret, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	csrJSON, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}
	_ = csrJSON // TODO: Make csrJSON optional arg and add to EnrollmentRequest below if present

	copServer, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	_ = args

	req := &idp.EnrollmentRequest{
		Name:   id,
		Secret: secret,
	}

	client, err := cutil.NewClient(copServer)
	if err != nil {
		return err
	}
	_, err = client.Enroll(req)

	return err
}

// Command assembles the definition of Command 'enroll'
var Command = &cli.Command{UsageText: usageText, Flags: flags, Main: myMain}
