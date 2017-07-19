/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"strings"
)

const (
	client    = "client"
	enroll    = "enroll"
	reenroll  = "reenroll"
	register  = "register"
	revoke    = "revoke"
	getcacert = "getcacert"
	gencsr    = "gencsr"
)

// Command is the object for fabric-ca-client commands
type Command struct {
	name string
}

// NewCommand will return command type
func NewCommand(commandName string) *Command {
	return &Command{
		name: strings.ToLower(commandName),
	}
}

// Certain client commands can only be executed if enrollment credentials
// are present
func (cmd *Command) requiresEnrollment() bool {
	return cmd.name != enroll && cmd.name != getcacert && cmd.name != gencsr
}

// Create default client configuration file only during an enroll command
func (cmd *Command) shouldCreateDefaultConfig() bool {
	return cmd.name == enroll || cmd.name == gencsr
}

func (cmd *Command) requiresUser() bool {
	return cmd.name != gencsr
}
