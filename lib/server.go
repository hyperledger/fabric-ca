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

package lib

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/util"
)

// Server is the fabric-ca server
type Server struct {
	// The home directory for the server
	HomeDir string
	// The server's configuration
	Config *ServerConfig
}

// Init initializes a fabric-ca server
// If key materials already exist and renew is true, regenerate the key materials
func (s *Server) Init(renew bool) error {
	log.Debugf("Init with home %s and config %+v", s.HomeDir, s.Config)

	// Make the path names absolute in the config
	s.makeFileNamesAbsolute()

	keyFile := s.Config.CA.Keyfile
	certFile := s.Config.CA.Certfile

	// If we aren't renewing and the key and cert files exist, do nothing
	if !renew {
		// If they both exist, the server was already initialized
		keyFileExists := util.FileExists(keyFile)
		certFileExists := util.FileExists(certFile)
		if keyFileExists && certFileExists {
			log.Info("The CA key and certificate files already exist")
			log.Infof("Key file location: %s", keyFile)
			log.Infof("Certificate file location: %s", certFile)
			return nil
		}
	}

	// Create the certificate request, copying from config
	ptr := &s.Config.CSR
	req := csr.CertificateRequest{
		CN:    ptr.CN,
		Names: ptr.Names,
		Hosts: ptr.Hosts,
		// FIXME: NewBasicKeyRequest only does ecdsa 256; use config
		KeyRequest:   csr.NewBasicKeyRequest(),
		CA:           ptr.CA,
		SerialNumber: ptr.SerialNumber,
	}

	// Initialize the CA now
	cert, _, key, err := initca.New(&req)
	if err != nil {
		return fmt.Errorf("Failed to initialize CA [%s]\nRequest was %#v", err, req)
	}

	// Store the key and certificate to file
	err = writeFile(keyFile, key, 0600)
	if err != nil {
		return fmt.Errorf("Failed to store key: %s", err)
	}
	err = writeFile(certFile, cert, 0644)
	if err != nil {
		return fmt.Errorf("Failed to store certificate: %s", err)
	}
	log.Info("The CA key and certificate files were generated")
	log.Infof("Key file location: %s", keyFile)
	log.Infof("Certificate file location: %s", certFile)
	return nil
}

// Make all file names in the config absolute
func (s *Server) makeFileNamesAbsolute() error {
	fields := []*string{
		&s.Config.CA.Certfile,
		&s.Config.CA.Keyfile,
	}
	for _, namePtr := range fields {
		abs, err := util.MakeFileAbs(*namePtr, s.HomeDir)
		if err != nil {
			return err
		}
		*namePtr = abs
	}
	return nil
}

func writeFile(file string, buf []byte, perm os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(file), perm)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, buf, perm)
}
