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
package lib

import (
	"crypto/x509"
	"io/ioutil"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
)

const (
	badcert              = "../testdata/expiredcert.pem"
	dsacert              = "../testdata/dsa-cert.pem"
	lowbitcert           = "../testdata/lowbitcert.pem"
	ecPrivKeyNotMatching = "../testdata/ec-key.pem"
	ecCert               = "../testdata/ec_cert.pem"
	ecPrivKeyMatching    = "../testdata/ec_key.pem"
	rsacert              = "../testdata/rsa.pem"
)

func TestBadCACertificates(t *testing.T) {
	certPEM, err := ioutil.ReadFile(badcert)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	testValidDates(cert, t)
	testValidUsages(cert, t)
	testValidCA(cert, t)
	testValidKeyType(cert, t)
	testValidKeySize(cert, t)
	testValidMatchingKeys(cert, t)
}

func testValidDates(cert *x509.Certificate, t *testing.T) {
	err := validateDates(cert)
	t.Log("validateDates Error: ", err)
	if err == nil {
		t.Error("Should have failed, expired CA certificate provided")
	}
}

func testValidUsages(cert *x509.Certificate, t *testing.T) {
	err := validateUsage(cert)
	t.Log("validateUsage Error: ", err)
	if err == nil {
		t.Error("Should have failed, incorrect usage specified for certificate")
	}
}

func testValidCA(cert *x509.Certificate, t *testing.T) {
	cert.IsCA = false
	err := validateIsCA(cert)
	t.Log("validateIsCA Error: ", err)
	if err == nil {
		t.Error("Should have failed, invalid value for IsCA")
	}
}

func testValidKeyType(cert *x509.Certificate, t *testing.T) {
	err := validateKeyType(cert)
	if err != nil {
		t.Errorf("Error occured during validation of a supported key type: %s", err)
	}

	certPEM, err := ioutil.ReadFile(dsacert)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	err = validateKeyType(cert)
	t.Log("validateKeyType-Bad Error: ", err)
	if err == nil {
		t.Error("Should have failed, unsupported key type DSA")
	}
}

func testValidKeySize(cert *x509.Certificate, t *testing.T) {
	err := validateKeySize(cert)
	if err != nil {
		t.Errorf("Failed to pass a ceritificate with valid key size: %s", err)
	}

	certPEM, err := ioutil.ReadFile(lowbitcert)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	err = validateKeySize(cert)
	t.Log("validateKeySize Error: ", err)
	if err == nil {
		t.Error("Should have failed, bit size is too low (1024) for certificate")
	}
}

func testValidMatchingKeys(cert *x509.Certificate, t *testing.T) {
	certPEM, err := ioutil.ReadFile(ecCert)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	err = validateMatchingKeys(cert, ecPrivKeyNotMatching)
	t.Log("validateMatchingKeys Error: ", err)
	if err == nil {
		t.Error("Should have failed, public key and private key do not match")
	}

	err = validateMatchingKeys(cert, ecPrivKeyMatching)
	if err != nil {
		t.Error("Failed to validate a matching key pair, error: ", err)
	}

	certPEM, err = ioutil.ReadFile(rsacert)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	err = validateMatchingKeys(cert, ecPrivKeyNotMatching)
	t.Log("validateMatchingKeys Error: ", err)
	if err == nil {
		t.Error("Should have failed, public key and private key do not match")
	}
}
