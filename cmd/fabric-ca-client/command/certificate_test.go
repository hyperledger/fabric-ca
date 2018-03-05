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
	"testing"

	"github.com/spf13/viper"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
)

// Unit Tests
func TestNewCertificateCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	certCmd := newCertificateCommand(cmd)
	assert.NotNil(t, certCmd)
}

func TestAddCertificateCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	certCmd := newCertificateCommand(cmd)
	assert.NotNil(t, certCmd)
	addCmd := addCertificateCommand(certCmd)
	assert.NotNil(t, addCmd)
}

func TestCreateCertificateCommand(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("GetViper").Return(viper.New())
	certCmd := createCertificateCommand(cmd)
	assert.NotNil(t, certCmd)
}

func TestBadPreRunCertificate(t *testing.T) {
	mockBadClientCmd := new(mocks.Command)
	mockBadClientCmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	cmd := newCertificateCommand(mockBadClientCmd)
	err := cmd.preRunCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Failed to initialize config", "Should have failed")
}

func TestGoodPreRunCertificate(t *testing.T) {
	mockGoodClientCmd := new(mocks.Command)
	mockGoodClientCmd.On("ConfigInit").Return(nil)
	mockGoodClientCmd.On("GetClientCfg").Return(&lib.ClientConfig{})
	cmd := newCertificateCommand(mockGoodClientCmd)
	err := cmd.preRunCertificate(&cobra.Command{}, []string{})
	assert.NoError(t, err, "Should not have failed")
}

func TestFailLoadIdentity(t *testing.T) {
	mockBadClientCmd := new(mocks.Command)
	mockBadClientCmd.On("LoadMyIdentity").Return(nil, errors.New("Failed to load identity"))
	cmd := newCertificateCommand(mockBadClientCmd)
	err := cmd.runListCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Failed to load identity", "Should have failed")
}
