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
