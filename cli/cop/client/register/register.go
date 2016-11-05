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

package register

import (
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cfssl/cli"
	cutil "github.com/hyperledger/fabric-cop/cli/cop/client"
	"github.com/hyperledger/fabric-cop/idp"

	"github.com/hyperledger/fabric-cop/util"
)

var usageText = `cop client register -- Register an ID with COP server and return an enrollment secret

Usage of client register command:
    Register a client with COP server:
        cop client register REGISTER-REQUEST-FILE COP-SERVER-ADDR

Arguments:
        RRJSON:             File contains registration info
        COP-SERVER-ADDR:    COP server address
Flags:
`

var flags = []string{}

func myMain(args []string, c cli.Config) error {

	regFile, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	buf, err := util.ReadFile(regFile)
	if err != nil {
		return err
	}

	callerID, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}
	_ = callerID

	regReq := new(idp.RegistrationRequest)
	err = json.Unmarshal(buf, regReq)
	if err != nil {
		return err
	}

	copServer, _, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	client, err := cutil.NewClient(copServer)
	if err != nil {
		return err
	}
	resp, err := client.Register(regReq)
	if err != nil {
		fmt.Printf("%+v", resp)
	}

	return err
}

// Command assembles the definition of Command 'enroll'
var Command = &cli.Command{UsageText: usageText, Flags: flags, Main: myMain}
