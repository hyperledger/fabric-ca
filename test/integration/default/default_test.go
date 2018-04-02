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

package defserver

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"

	"github.com/cloudflare/cfssl/config"
)

const (
	cmdName    = "fabric-ca-client"
	clientHome = "clientHome"
)

var (
	defaultServer          *lib.Server
	defaultServerPort      = 7054
	defaultServerEnrollURL = fmt.Sprintf("http://admin:adminpw@localhost:%d", defaultServerPort)
	defaultServerHomeDir   = "defaultServerDir"
)

func TestMain(m *testing.M) {
	metadata.Version = "1.1.0"

	defaultServer, err := getDefaultServer()
	if err != nil {
		log.Errorf("Failed to get instance of server: %s", err)
		os.Exit(1)
	}

	err = defaultServer.Start()
	if err != nil {
		log.Errorf("Failed to start server: %s", err)
		os.Exit(1)
	}

	rc := m.Run()

	err = defaultServer.Stop()
	if err != nil {
		log.Errorf("Failed to stop server: %s, integration test results: %d", err, rc)
		os.Exit(1)
	}

	os.RemoveAll(defaultServerHomeDir)
	os.Exit(rc)
}

func TestListCertificateCmdNegative(t *testing.T) {
	var err error
	// Remove default client home location to remove any existing enrollment information
	os.RemoveAll(filepath.Dir(util.GetDefaultConfigFile("fabric-ca-client")))

	// Command should fail if caller has not yet enrolled
	err = command.RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Enrollment information does not exist", "Should have failed to call command, if caller has not yet enrolled")

	// Enroll a user that will be used for subsequent certificate commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	// Test with --revocation flag
	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-30d:-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, only one ':' specified need to specify two '::'")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "30d::-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on starting duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "+30d::15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on ending duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "+30d::+15y"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, invalid duration type (y)")

	// Test with --expiration flag
	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "-30d:-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, only one ':' specified need to specify two '::'")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "30d::-15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on starting duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "+30d::15d"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, missing +/- on ending duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "1/30/18::2/14/2018"})
	t.Log("Error: ", err)
	assert.Error(t, err, "Should fail, using slashes instead of dashes in time format")
}

func TestListCertificateCmdPositive(t *testing.T) {
	var err error
	// Enroll a user that will be used for subsequent certificate commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = command.RunMain([]string{cmdName, "reenroll", "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d"})
	assert.NoError(t, err, "Failed to get certificates")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "-30d::+15d"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-30d::-15d"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation duration")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "2018-01-01::2018-01-31"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "2018-01-01::2018-01-31"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "2018-01-01T01:00:00Z::2018-01-31T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted expiration date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "2018-01-01T01:00:00Z::2018-01-31T23:00:00Z"})
	assert.NoError(t, err, "Failed to parse a correctly formatted revocation date range")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--expiration", "now::+15d"})
	assert.NoError(t, err, "Failed to parse a expiration date range using 'now'")

	err = command.RunMain([]string{cmdName, "certificate", "list", "-d", "--id", "admin", "--revocation", "-15d::now"})
	assert.NoError(t, err, "Failed to parse a revocation date range using 'now'")
}

func TestGetCertificatesTimeInput(t *testing.T) {
	os.RemoveAll(clientHome)
	defer os.RemoveAll(clientHome)

	var err error

	client := lib.GetTestClient(defaultServerPort, clientHome)
	resp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	util.FatalError(t, err, "Failed to enroll user 'admin'")

	admin := resp.Identity

	negativeTimeTestCases(t, admin)
	positiveTimeTestCases(t, admin)
}

func negativeTimeTestCases(t *testing.T, admin *lib.Identity) {
	req := &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			EndTime: "-30y",
		},
	}
	err := admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for expiration end time")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-30y",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time frame for revocation end time")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-IOd",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "-30.5",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")

	req = &api.GetCertificatesRequest{
		Revoked: api.TimeRange{
			EndTime: "2018-01-01T00:00:00",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.Error(t, err, "Incorrect time format")
}

func positiveTimeTestCases(t *testing.T, admin *lib.Identity) {
	req := &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "+30d",
		},
	}
	err := admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse correct time")

	req = &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "2018-01-01",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse date/time without the time")

	req = &api.GetCertificatesRequest{
		Expired: api.TimeRange{
			StartTime: "2018-01-01T00:00:00Z",
		},
	}
	err = admin.GetCertificates(req, nil)
	assert.NoError(t, err, "Failed to parse date/time")
}

func getDefaultServer() (*lib.Server, error) {
	affiliations := map[string]interface{}{
		"hyperledger": map[string]interface{}{
			"fabric":    []string{"ledger", "orderer", "security"},
			"fabric-ca": nil,
			"sdk":       nil,
		},
		"org2":      []string{"dept1"},
		"org1":      nil,
		"org2dept1": nil,
	}
	profiles := map[string]*config.SigningProfile{
		"tls": &config.SigningProfile{
			Usage:        []string{"signing", "key encipherment", "server auth", "client auth", "key agreement"},
			ExpiryString: "8760h",
		},
		"ca": &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "8760h",
			CAConstraint: config.CAConstraint{
				IsCA:       true,
				MaxPathLen: 0,
			},
		},
	}
	defaultProfile := &config.SigningProfile{
		Usage:        []string{"cert sign"},
		ExpiryString: "8760h",
	}
	srv := &lib.Server{
		Config: &lib.ServerConfig{
			Port:  defaultServerPort,
			Debug: true,
		},
		CA: lib.CA{
			Config: &lib.CAConfig{
				Intermediate: lib.IntermediateCA{
					ParentServer: lib.ParentServer{
						URL: "",
					},
				},
				Affiliations: affiliations,
				Registry: lib.CAConfigRegistry{
					MaxEnrollments: -1,
				},
				Signing: &config.Signing{
					Profiles: profiles,
					Default:  defaultProfile,
				},
				Version: "1.1.0", // The default test server/ca should use the latest version
			},
		},
		HomeDir: defaultServerHomeDir,
	}
	// The bootstrap user's affiliation is the empty string, which
	// means the user is at the affiliation root
	err := srv.RegisterBootstrapUser("admin", "adminpw", "")
	if err != nil {
		return nil, err
	}
	return srv, nil
}
