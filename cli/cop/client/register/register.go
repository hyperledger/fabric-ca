package register

import (
	"encoding/json"

	"github.com/cloudflare/cfssl/cli"
	cop "github.com/hyperledger/fabric-cop/api"

	lib "github.com/hyperledger/fabric-cop/lib/defaultImpl"
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

	regReq := new(cop.RegisterRequest)
	err = json.Unmarshal(buf, regReq)
	if err != nil {
		return err
	}

	regReq.CallerID = callerID

	copServer, _, err := cli.PopFirstArgument(args)
	if err != nil {
		return err
	}

	// mgr := cop.Mgr
	mgr, _ := lib.NewMgr()
	cop.SetMgr(mgr)
	client := cop.NewClient()
	client.SetServerAddr(copServer)
	err = client.Register(regReq)

	return err
}

// Command assembles the definition of Command 'enroll'
var Command = &cli.Command{UsageText: usageText, Flags: flags, Main: myMain}
