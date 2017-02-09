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

package util

import (
	"fmt"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// CmdRunBegin is called at the beginning of each cobra run function
func CmdRunBegin() {
	// If -d or --debug, set debug logging level
	if viper.GetBool("debug") {
		log.Level = log.LevelDebug
	}
}

// FlagString sets up a flag for a string, binding it to its name
func FlagString(flags *pflag.FlagSet, name, short string, def string, desc string) {
	flags.StringP(name, short, def, desc)
	bindFlag(flags, name)
}

// FlagInt sets up a flag for an int, binding it to its name
func FlagInt(flags *pflag.FlagSet, name, short string, def int, desc string) {
	flags.IntP(name, short, def, desc)
	bindFlag(flags, name)
}

// FlagBool sets up a flag for a bool, binding it to its name
func FlagBool(flags *pflag.FlagSet, name, short string, def bool, desc string) {
	flags.BoolP(name, short, def, desc)
	bindFlag(flags, name)
}

// common binding function
func bindFlag(flags *pflag.FlagSet, name string) {
	flag := flags.Lookup(name)
	if flag == nil {
		panic(fmt.Errorf("failed to lookup '%s'", name))
	}
	viper.BindPFlag(name, flag)
}
