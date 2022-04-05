/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package defserver

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/cmd/fabric-ca-client/command"
	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/metadata"
	"github.com/hyperledger/fabric-ca/util"
)

const (
	cmdName = "fabric-ca-client"
)

var (
	defaultServer          *lib.Server
	defaultServerPort      = 7055
	defaultServerEnrollURL = fmt.Sprintf("http://admin:adminpw@localhost:%d", defaultServerPort)
	defaultServerHomeDir   = "certExpiryServerDir"
	storeCertsDir          = "/tmp/testCertsCertExpiry"
	clientCAHome           = "/tmp/certExpiryCaHome"
)

func TestMain(m *testing.M) {
	var err error

	metadata.Version = "1.1.0"
	os.Setenv("FABRIC_CA_SERVER_SIGNING_DEFAULT_EXPIRY", "1m")
	os.Setenv("FABRIC_CA_CLIENT_HOME", clientCAHome)

	os.RemoveAll(defaultServerHomeDir)
	os.RemoveAll(storeCertsDir)
	os.RemoveAll(clientCAHome)
	defaultServer, err = getDefaultServer()
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
	os.RemoveAll(storeCertsDir)
	os.RemoveAll(clientCAHome)
	os.Exit(rc)
}

func TestReenrollExpiredCert(t *testing.T) {
	var err error

	// Enroll a user that will be used for subsequent certificate commands
	err = command.RunMain([]string{cmdName, "enroll", "-u", defaultServerEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user")

	// Register a new user
	err = command.RunMain([]string{cmdName, "register", "-u", defaultServerEnrollURL, "-d", "--csr.keyrequest.reusekey", "--id.name", "user1", "--id.secret", "user1pw", "--id.type", "client"})
	util.FatalError(t, err, "Failed to register new user1")

	userServiceEnrollURL := fmt.Sprintf("http://user1:user1pw@localhost:%d", defaultServerPort)

	// Enroll and then reenroll to check
	err = command.RunMain([]string{cmdName, "enroll", "-u", userServiceEnrollURL, "-d"})
	util.FatalError(t, err, "Failed to enroll user1")

	err = command.RunMain([]string{cmdName, "reenroll", "-u", userServiceEnrollURL, "-d", "--csr.keyrequest.reusekey"})
	util.FatalError(t, err, "Failed to reenroll user1")

	log.Infof("Tested re-enroll of id, waiting for cert to expiry before testing re-enroll\n")
	time.Sleep(2 * time.Minute)

	// within the setting in the CA config reenrollIgnoreCertExpiry this call would normally fail
	err = command.RunMain([]string{cmdName, "reenroll", "-u", userServiceEnrollURL, "-d", "--csr.keyrequest.reusekey"})
	util.FatalError(t, err, "Failed to reenroll user1 %s", time.Now())
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
			ExpiryString: "1m",
		},
		"ca": &config.SigningProfile{
			Usage:        []string{"cert sign", "crl sign"},
			ExpiryString: "1m",
			CAConstraint: config.CAConstraint{
				IsCA:       true,
				MaxPathLen: 0,
			},
		},
	}
	defaultProfile := &config.SigningProfile{
		Usage:        []string{"cert sign"},
		ExpiryString: "1m",
		Expiry:       time.Minute * 1, // set to force certs to expiry quickly
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
				CA: lib.CAInfo{
					ReenrollIgnoreCertExpiry: true,
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
