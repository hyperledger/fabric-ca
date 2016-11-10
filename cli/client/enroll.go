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
	"io/ioutil"
	"path/filepath"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"

	"github.com/hyperledger/fabric-cop/idp"
	"github.com/hyperledger/fabric-cop/util"
)

var enrollUsageText = `cop client enroll -- Enroll with COP server

Usage of client enroll command:
    Enroll a client and get an ecert:
        cop client enroll ID SECRET COP-SERVER-ADDR

Arguments:
        ID:               Enrollment ID
        SECRET:           Enrollment secret returned by register
        COP-SERVER-ADDR:  COP server address
				CSRJSON:          Certificate Signing Request JSON information (Optional)

Flags:
`

var enrollFlags = []string{}

func enrollMain(args []string, c cli.Config) error {
	log.Debug("in myMain of 'cop client enroll'")

	id, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	secret, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	copServer, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	req := &idp.EnrollmentRequest{
		Name:   id,
		Secret: secret,
	}

	if len(args) > 0 {
		if filepath.Ext(args[0]) == ".json" {
			csrJSON, _, err := cli.PopFirstArgument(args)
			if err != nil {
				return err
			}
			csrJSONBytes, err := ioutil.ReadFile(csrJSON)
			if err != nil {
				return err
			}

			var CertRequest csr.CertificateRequest
			util.Unmarshal(csrJSONBytes, &CertRequest, "Certificate request")
			req.CR = &CertRequest
		}
		log.Debug("Other argument besides optional csr provided")
	}

	_ = args

	client, err := NewClient(copServer)
	if err != nil {
		return err
	}
	ID, err := client.Enroll(req)
	if err != nil {
		return err
	}

	idByte, err := ID.Serialize()
	if err != nil {
		return err
	}
	home := util.GetDefaultHomeDir()
	err = util.WriteFile(home+"/client.json", idByte, 0644)
	if err != nil {
		return err
	}

	return nil
}

// EnrollCommand is the enroll command
var EnrollCommand = &cli.Command{UsageText: enrollUsageText, Flags: enrollFlags, Main: enrollMain}
