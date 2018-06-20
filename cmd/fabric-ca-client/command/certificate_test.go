/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command/mocks"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
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
	mockBadClientCmd.On("SetDefaultLogLevel", "warning")
	mockBadClientCmd.On("ConfigInit").Return(errors.New("Failed to initialize config"))
	cmd := newCertificateCommand(mockBadClientCmd)
	err := cmd.preRunCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Failed to initialize config", "Should have failed")
}

func TestGoodPreRunCertificate(t *testing.T) {
	mockGoodClientCmd := new(mocks.Command)
	mockGoodClientCmd.On("SetDefaultLogLevel", "warning")
	mockGoodClientCmd.On("ConfigInit").Return(nil)
	mockGoodClientCmd.On("GetClientCfg").Return(&lib.ClientConfig{})
	cmd := newCertificateCommand(mockGoodClientCmd)
	err := cmd.preRunCertificate(&cobra.Command{}, []string{})
	assert.NoError(t, err, "Should not have failed")
}

func TestFailLoadIdentity(t *testing.T) {
	mockBadClientCmd := new(mocks.Command)
	mockBadClientCmd.On("SetDefaultLogLevel", "warning")
	mockBadClientCmd.On("LoadMyIdentity").Return(nil, errors.New("Failed to load identity"))
	cmd := newCertificateCommand(mockBadClientCmd)
	err := cmd.runListCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Failed to load identity", "Should have failed")
}

func TestBadRunListCertificate(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("SetDefaultLogLevel", "warning")
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Expiration: "30d:15d",
	}
	err := certCmd.runListCertificate(&cobra.Command{}, []string{})
	util.ErrorContains(t, err, "Invalid expiration format, expecting", "Should have failed")
}

func TestBadExpirationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("SetDefaultLogLevel", "warning")
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Expiration: "30d:15d",
	}
	err := certCmd.getCertListReq()
	util.ErrorContains(t, err, "Invalid expiration format, expecting", "Should have failed")

	certCmd.timeArgs = timeArgs{
		Expiration: "01/30/2015::15d",
	}
	err = certCmd.getCertListReq()
	util.ErrorContains(t, err, "Invalid expiration format, use '-' instead of '/'", "Should have failed")
}

func TestGoodExpirationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("SetDefaultLogLevel", "warning")
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Expiration: "30d::15d",
	}
	err := certCmd.getCertListReq()
	assert.NoError(t, err, "Failed to parse properly formated expiration time range")
}

func TestBadRevocationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("SetDefaultLogLevel", "warning")
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Revocation: "30d:15d",
	}
	err := certCmd.getCertListReq()
	util.ErrorContains(t, err, "Invalid revocation format, expecting", "Should have failed")

	certCmd.timeArgs = timeArgs{
		Revocation: "1/30/2015::15d",
	}
	err = certCmd.getCertListReq()
	util.ErrorContains(t, err, "Invalid revocation format, use '-' instead of '/'", "Should have failed")
}

func TestGoodRevocationTime(t *testing.T) {
	cmd := new(mocks.Command)
	cmd.On("SetDefaultLogLevel", "warning")
	cmd.On("LoadMyIdentity").Return(&lib.Identity{}, nil)
	certCmd := newCertificateCommand(cmd)
	certCmd.timeArgs = timeArgs{
		Revocation: "30d::15d",
	}
	err := certCmd.getCertListReq()
	assert.NoError(t, err, "Failed to parse properly formated revocation time range")
}

func TestTimeRangeWithNow(t *testing.T) {
	timeNow := time.Now().UTC().Format(time.RFC3339)
	timeStr := getTime("now")
	assert.Equal(t, timeNow, timeStr)
}
