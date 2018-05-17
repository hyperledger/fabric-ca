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

package command

import (
	"reflect"
	"testing"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewGetCACertCmd(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	getcacertCmd := newGetCAInfoCmd(cmd)
	assert.NotNil(t, getcacertCmd)
}

func TestGetCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	getcacertCmd := newGetCAInfoCmd(cmd)
	cobraCmd := getcacertCmd.getCommand()
	assert.NotNil(t, cobraCmd)
	assert.Equal(t, cobraCmd.Name(), "getcainfo")
	assert.Equal(t, cobraCmd.Short, GetCAInfoCmdShortDesc)
	assert.Equal(t, cobraCmd.Use, GetCAInfoCmdUsage)

	f1 := reflect.ValueOf(cobraCmd.PreRunE)
	f2 := reflect.ValueOf(getcacertCmd.preRunGetCACert)
	assert.Equal(t, f1.Pointer(), f2.Pointer(), "PreRunE function variable of the getcacert cobra command must be preRunGetCACert function of the getCACert struct")

	f1 = reflect.ValueOf(cobraCmd.RunE)
	f2 = reflect.ValueOf(getcacertCmd.runGetCACert)
	assert.Equal(t, f1.Pointer(), f2.Pointer(), "RunE function variable of the getcacert cobra command must be runGetCACert function of the getCACert struct")
}

func TestBadConfigPreRunGetCACert(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	getcacertCmd := newGetCAInfoCmd(cmd)
	cobraCmd := getcacertCmd.getCommand()
	err := getcacertCmd.preRunGetCACert(cobraCmd, []string{})
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "Failed to initialize config")
}

func TestGoodConfigPreRunGetCACert(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	cmd.On("ConfigInit").Return(nil)
	cmd.On("GetClientCfg").Return(&lib.ClientConfig{})
	getcacertCmd := newGetCAInfoCmd(cmd)
	cobraCmd := getcacertCmd.getCommand()
	err := getcacertCmd.preRunGetCACert(cobraCmd, []string{})
	assert.NoError(t, err)
}
