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
	cmd "github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"

	"github.com/cloudflare/cfssl/config"
)

const (
	cmdName = "fabric-ca-client"
)

var (
	defaultServer          *lib.Server
	defaultServerEnrollURL = fmt.Sprintf("http://admin:adminpw@localhost:7054")
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

func TestListCertificateCmd(t *testing.T) {
	// Remove default client home location to remove any existing enrollment information
	os.RemoveAll(filepath.Dir(util.GetDefaultConfigFile("fabric-ca-client")))

	// Command should fail if caller has not yet enrolled
	err := cmd.RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Enrollment information does not exist", "Should have failed to call command, if caller has not yet enrolled")

	// Enroll a user that will be used for subsequent certificate commands
	err = cmd.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	err = cmd.RunMain([]string{cmdName, "certificate", "list", "-d"})
	util.ErrorContains(t, err, "Not Implemented", "Should fail, not yet implemented")
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
			Port:  7054,
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
