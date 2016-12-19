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

package tcert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/cloudflare/cfssl/log"
)

func TestTCertWithoutAttribute(t *testing.T) {

	log.Level = log.LevelDebug

	// Get a manager configured with 10 minute lifetime for generated TCerts
	mgr := getMgr("10m", t)
	if mgr == nil {
		return
	}

	ecert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		return
	}

	resp, err := mgr.GetBatch(&GetBatchRequest{
		Count:  1,
		PreKey: "anyroot",
	}, ecert)
	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)
		return
	}
	if len(resp.TCerts) != 1 {
		t.Errorf("Returned incorrect number of TCerts: expecting 1 but found %d", len(resp.TCerts))
	}

}

func TestTCertWitAttributes(t *testing.T) {

	log.Level = log.LevelDebug

	// Get a manager configured with 10 minute lifetime for generated TCerts
	mgr := getMgr("10m", t)
	if mgr == nil {
		return
	}

	ecert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		return
	}
	var Attrs = []Attribute{
		{
			Name:  "SSN",
			Value: "123-456-789",
		},

		{
			Name:  "Income",
			Value: "USD",
		},
	}
	resp, err := mgr.GetBatch(&GetBatchRequest{
		Count:        2,
		EncryptAttrs: true,
		Attrs:        Attrs,
		PreKey:       "anotherprekey",
	}, ecert)
	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)
		return
	}
	if len(resp.TCerts) != 2 {
		t.Errorf("Returned incorrect number of certs: expecting 2 but found %d", len(resp.TCerts))
	}

}

func getMgr(validityPeriod string, t *testing.T) *Mgr {
	caKey, err := LoadKey("../../testdata/ec-key.pem")
	if err != nil {
		t.Errorf("Failed loading CA key: %s", err)
		return nil
	}
	caCert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		t.Errorf("Failed loading CA cert: %s", err)
		return nil
	}
	mgr, err := NewMgr(caCert, caKey)
	if err != nil {
		t.Errorf("Failed creating TCert manager: %s", err)
		return nil
	}
	return mgr
}

func LoadCert(path string) (*x509.Certificate, error) {
	certBuf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certBuf)
	if block == nil {
		return nil, fmt.Errorf("Failed to PEM decode certificate from %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error from x509.ParseCertificate: %s", err)
	}
	return cert, nil
}

func LoadKey(path string) (interface{}, error) {
	keyBuf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := GetPrivateKey(keyBuf)
	if err != nil {
		return nil, err
	}
	return key, nil
}

//GetPrivateKey returns ecdsa.PrivateKey or rsa.privateKey object for the private Key Bytes
//Der Format is not supported
func GetPrivateKey(privateKeyBuff []byte) (interface{}, error) {

	var err error
	var privateKey interface{}

	block, _ := pem.Decode(privateKeyBuff)
	if block == nil {
		privateKey, err = parsePrivateKey(privateKeyBuff)
		if err != nil {
			log.Error("Private Key in DER format is not generated")
			return nil, errors.New("Private Key in DER format is not generated")
		}
		//return nil, errors.New("Failed decoding PEM Block")
	} else {
		privateKey, err = parsePrivateKey(block.Bytes)
		if err != nil {
			log.Error("Private Key in PEM format is not generated")
			return nil, errors.New("Private Key in PEM format is not generated")
		}
	}

	switch privateKey := privateKey.(type) {
	case *rsa.PrivateKey:
		return privateKey, nil
	case *ecdsa.PrivateKey:
		return privateKey, nil
	default:
		return nil, errors.New("Key is not of correct type")
	}

}

// parsePrivateKey parses private key
func parsePrivateKey(der []byte) (interface{}, error) {

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {

		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}
