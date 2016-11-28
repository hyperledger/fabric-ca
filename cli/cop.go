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

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/bundle"
	"github.com/cloudflare/cfssl/cli/certinfo"
	"github.com/cloudflare/cfssl/cli/gencert"
	"github.com/cloudflare/cfssl/cli/gencrl"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/cli/info"
	"github.com/cloudflare/cfssl/cli/ocspdump"
	"github.com/cloudflare/cfssl/cli/ocsprefresh"
	"github.com/cloudflare/cfssl/cli/ocspserve"
	"github.com/cloudflare/cfssl/cli/ocspsign"
	"github.com/cloudflare/cfssl/cli/printdefault"
	"github.com/cloudflare/cfssl/cli/revoke"
	"github.com/cloudflare/cfssl/cli/scan"
	"github.com/cloudflare/cfssl/cli/selfsign"
	"github.com/cloudflare/cfssl/cli/serve"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/cli/version"
	"github.com/hyperledger/fabric-cop/cli/client"
	"github.com/hyperledger/fabric-cop/cli/server"

	_ "github.com/go-sql-driver/mysql" // import to support MySQL
	_ "github.com/lib/pq"              // import to support Postgres
	_ "github.com/mattn/go-sqlite3"    // import to support SQLite3
)

var usage = `cop client       - client-related commands
cop server       - server related commands
cop cfssl        - all cfssl commands

For help, type "cop client", "cop server", or "cop cfssl".
`

// COPMain is the COP main
func COPMain(args []string) int {
	if len(args) <= 1 {
		fmt.Println(usage)
		return 1
	}
	flag.Usage = nil // this is set to nil for testabilty
	cmd := args[1]
	os.Args = args[1:]
	var err error
	switch cmd {
	case "client":
		err = client.Command()
	case "server":
		err = server.Command()
	case "cfssl":
		err = cfsslCommand()
	default:
		fmt.Println(usage)
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func cfsslCommand() error {
	cmds := map[string]*cli.Command{
		"bundle":         bundle.Command,
		"certinfo":       certinfo.Command,
		"sign":           sign.Command,
		"serve":          serve.Command,
		"version":        version.Command,
		"genkey":         genkey.Command,
		"gencert":        gencert.Command,
		"gencrl":         gencrl.Command,
		"ocspdump":       ocspdump.Command,
		"ocsprefresh":    ocsprefresh.Command,
		"ocspsign":       ocspsign.Command,
		"ocspserve":      ocspserve.Command,
		"selfsign":       selfsign.Command,
		"scan":           scan.Command,
		"info":           info.Command,
		"print-defaults": printdefaults.Command,
		"revoke":         revoke.Command,
	}

	// Replace "cfssl" with "cop cfssl" in all usage messages
	for _, cmd := range cmds {
		cmd.UsageText = strings.Replace(cmd.UsageText, "cfssl", "cop cfssl", -1)
	}

	return cli.Start(cmds)
}

func main() {
	os.Exit(COPMain(os.Args))
}
