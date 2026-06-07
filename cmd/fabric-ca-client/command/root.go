/*
Copyright IBM Corp. 2018 All Rights Reserved.

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

package command

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// RunMain is the fabric-ca client main
func RunMain(args []string) error {
	// Save the os.Args
	saveOsArgs := os.Args
	os.Args = args

	ccmd := NewCommand("")
	if len(args) > 1 {
		ccmd.name = strings.ToLower(resolveCommandName(ccmd.rootCmd, args[1:]))
	}
	err := ccmd.Execute()

	// Restore original os.Args
	os.Args = saveOsArgs

	return err
}

// resolveCommandName returns the top-level subcommand selected by args using
// the same parsing rules as cobra, so global flags may appear before the
// subcommand name.
func resolveCommandName(root *cobra.Command, args []string) string {
	cmd, _, err := root.Find(args)
	if err != nil || cmd == nil || cmd == root {
		return ""
	}
	for cmd.Parent() != nil && cmd.Parent() != root {
		cmd = cmd.Parent()
	}
	return cmd.Name()
}
