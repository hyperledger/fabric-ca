/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package server

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
)

func TestInitCA(t *testing.T) {

	s := new(Server)
	FCAHome, err := s.CreateHome()
	if err != nil {
		log.Fatalf("Failed to create fabric-ca home directory.")
	}

	req := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}

	csrFileBytes, err := cli.ReadStdin("../../testdata/csr_dsa.json")
	if err != nil {
		return
	}

	err = json.Unmarshal(csrFileBytes, &req)
	if err != nil {
		return
	}

	var c cli.Config

	c = cli.Config{
		IsCA: true,
	}

	if c.IsCA {
		var key, csrPEM, cert []byte
		cert, csrPEM, key, err = initca.New(&req)
		if err != nil {
			return
		}

		cli.PrintCert(key, csrPEM, cert)
		certerr := ioutil.WriteFile(path.Join(FCAHome, "server-cert.pem"), cert, 0755)
		if certerr != nil {
			log.Fatal("Error writing server-cert.pem to FABRIC_CA_HOME directory")
		}
		keyerr := ioutil.WriteFile(path.Join(FCAHome, "server-key.pem"), key, 0755)
		if keyerr != nil {
			log.Fatal("Error writing server-key.pem to FABRIC_CA_HOME directory")
		}
	} else {
		var ca *csr.CAConfig
		req.CA = ca
		if req.CA != nil {
			err = errors.New("ca section only permitted in initca")
			return
		}

		csrPEM, key, csrerr := csr.ParseRequest(&req)
		if csrerr != nil {
			key = nil
			return
		}
		cli.PrintCert(key, csrPEM, nil)
	}
}

func TestInitNOTCA(t *testing.T) {
	req := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}

	csrFileBytes, err := cli.ReadStdin("../../testdata/csr_dsa.json")
	if err != nil {
		return
	}
	err = json.Unmarshal(csrFileBytes, &req)
	if err != nil {
		return
	}
	ca := &csr.CAConfig{
		Expiry: "testing expiry",
	}
	req.CA = ca
	if req.CA != nil {
		err = errors.New("ca section only permitted in initca")
		return
	}

	csrPEM, key, csrerr := csr.ParseRequest(&req)
	if csrerr != nil {
		key = nil
		return
	}
	cli.PrintCert(key, csrPEM, nil)
}

func TestMissingCSRFile(t *testing.T) {
	osArgs := os.Args
	os.Args = []string{"server", "init"}
	os.Args = osArgs
	_, args, err := cli.PopFirstArgument(os.Args)
	if err != nil {
		t.Fatal("Failed due to missing csrFile")
	}
	var c cli.Config
	initerr := initMain(args, c)
	if initerr == nil {
		t.Fatal("Should have failed due to missing csrFile")
	}
}

func TestInitCommand(t *testing.T) {
	osArgs := os.Args
	CSRJSON := "../../testdata/csr_dsa.json"
	os.Args = []string{"server", "init", CSRJSON}
	Command()
	os.Args = osArgs
}
