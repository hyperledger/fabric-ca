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
