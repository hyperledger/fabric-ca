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

package lib

import (
	"io/ioutil"

	"github.com/cloudflare/cfssl/log"
	proto "github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
)

// IssuerCredential represents CA's idemix credential
type IssuerCredential interface {
	Load() error
	Store() error
	GetIssuerKey() (*idemix.IssuerKey, error)
	SetIssuerKey(key *idemix.IssuerKey)
}

type issuerCredential struct {
	pubKeyFile    string
	secretKeyFile string
	issuerKey     *idemix.IssuerKey
}

func newIssuerCredential(pubKeyFile, secretKeyFile string) IssuerCredential {
	return &issuerCredential{
		pubKeyFile:    pubKeyFile,
		secretKeyFile: secretKeyFile,
	}
}

func (ic *issuerCredential) Load() error {
	pubKeyFileExists := util.FileExists(ic.pubKeyFile)
	secretKeyFileExists := util.FileExists(ic.secretKeyFile)
	if pubKeyFileExists && secretKeyFileExists {
		log.Info("The issuer public and secret key files already exist")
		log.Infof("   secret key file location: %s", ic.secretKeyFile)
		log.Infof("   public key file location: %s", ic.pubKeyFile)
		pubKeyBytes, err := ioutil.ReadFile(ic.pubKeyFile)
		if err != nil {
			return errors.Wrapf(err, "Failed to read issuer public key")
		}
		pubKey := &idemix.IssuerPublicKey{}
		err = proto.Unmarshal(pubKeyBytes, pubKey)
		if err != nil {
			return errors.Wrapf(err, "Failed to unmarshal issuer public key bytes")
		}
		err = pubKey.Check()
		if err != nil {
			return errors.Wrapf(err, "Issuer public key check failed")
		}
		privKey, err := ioutil.ReadFile(ic.secretKeyFile)
		if err != nil {
			return errors.Wrapf(err, "Failed to read issuer secret key")
		}
		ic.issuerKey = &idemix.IssuerKey{
			IPk: pubKey,
			ISk: privKey,
		}
	}
	return nil
}

func (ic *issuerCredential) Store() error {
	ik, err := ic.GetIssuerKey()
	if err != nil {
		return err
	}

	ipkBytes, err := proto.Marshal(ik.IPk)
	if err != nil {
		return errors.New("Failed to marshal issuer public key")
	}

	err = util.WriteFile(ic.pubKeyFile, ipkBytes, 0644)
	if err != nil {
		log.Errorf("Failed to store issuer public key: %s", err.Error())
		return errors.New("Failed to store issuer public key")
	}

	err = util.WriteFile(ic.secretKeyFile, ik.ISk, 0644)
	if err != nil {
		log.Errorf("Failed to store issuer secret key: %s", err.Error())
		return errors.New("Failed to store issuer secret key")
	}

	log.Infof("The issuer key was successfully stored. The public key is at: %s, secret key is at: %s",
		ic.pubKeyFile, ic.secretKeyFile)
	return nil
}

func (ic *issuerCredential) GetIssuerKey() (*idemix.IssuerKey, error) {
	if ic.issuerKey == nil {
		return nil, errors.New("Issuer key is not set")
	}
	return ic.issuerKey, nil
}

func (ic *issuerCredential) SetIssuerKey(key *idemix.IssuerKey) {
	ic.issuerKey = key
}
