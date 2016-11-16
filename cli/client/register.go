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
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cfssl/cli"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/hyperledger/fabric-cop/idp"

	"github.com/hyperledger/fabric-cop/util"
)

var registerUsageText = `cop client register -- Register an ID with COP server and return an enrollment secret

Usage of client register command:
    Register a client with COP server:
        cop client register REGISTER-REQUEST-FILE COP-SERVER-ADDR

Arguments:
        RRJSON:             File contains registration info
        COP-SERVER-ADDR:    COP server address
Flags:
`

var registerFlags = []string{}

func registerMain(args []string, c cli.Config) error {

	regFile, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	buf, err := util.ReadFile(regFile)
	if err != nil {
		return err
	}

	regReq := new(idp.RegistrationRequest)
	err = json.Unmarshal(buf, regReq)
	if err != nil {
		return err
	}

	copServer, _, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	client, err := NewClient(copServer)
	if err != nil {
		return err
	}

	id, err := client.LoadMyIdentity()
	regReq.Registrar = id
	resp, err := client.Register(regReq)
	if err != nil {
		return err
	}

	secretBytes, err := base64.StdEncoding.DecodeString(resp.Secret)
	if err != nil {
		cop.WrapError(err, cop.EnrollingUserError, "Failed to decode string to bytes")
	}

	fmt.Printf("One time password: %s\n", string(secretBytes))

	return nil
}

// RegisterCommand is the register command
var RegisterCommand = &cli.Command{UsageText: registerUsageText, Flags: registerFlags, Main: registerMain}
