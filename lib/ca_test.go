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
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/pkcs11"
	"github.com/stretchr/testify/assert"
)

const (
	testdir              = "../testdata"
	dbname               = "fabric-ca-server.db"
	badcert              = "../testdata/expiredcert.pem"
	dsacert              = "../testdata/dsa-cert.pem"
	lowbitcert           = "../testdata/lowbitcert.pem"
	ecPrivKeyNotMatching = "../testdata/ec-key.pem"
	ecCert               = "../testdata/ec_cert.pem"
	ecPrivKeyMatching    = "../testdata/ec_key.pem"
	rsacert              = "../testdata/rsa.pem"
	badusage             = "../testdata/tls_server-cert.pem"
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
	testValidCA(cert, t)
	testValidKeyType(cert, t)
	testValidKeySize(cert, t)
	testValidMatchingKeys(cert, t)
	testValidUsages(cert, t)
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

	certPEM, err := ioutil.ReadFile(badusage)
	if err != nil {
		t.Fatal(err)
	}

	cert, err = util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	err = validateUsage(cert)
	t.Log("validateUsage Error: ", err)
	if assert.Error(t, err, "Should have failed, missing 'Cert Sign' key usage") {
		assert.Contains(t, err.Error(), "'Cert Sign' key usage is required")
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

func TestCAInit(t *testing.T) {
	var cfg CAConfig
	var srv Server
	var caCert = "ca-cert.pem"
	var caKey = "ca-key.pem"

	orgwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %s", err)
	}
	t.Logf("====== orgwd %v", orgwd)
	confDir, err := cdTmpTestDir("TestCAInit")
	if err != nil {
		t.Fatalf("failed to cd to tmp dir: %s", err)
	}
	defer func() {
		err = os.Chdir(orgwd)
		if err != nil {
			t.Fatalf("failed to cd to %v: %s", orgwd, err)
		}
	}()
	t.Logf("confDir: %v", confDir)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %s", err)
	}
	t.Log("Working dir", wd)
	defer func() {
		err = os.RemoveAll(wd)
		if err != nil {
			t.Fatalf("RemoveAll failed: %s", err)
		} else {
			t.Logf("Removed all: %s", wd)
		}
	}()
	ca, err := NewCA(confDir, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA FAILED")
	}

	// BCCSP error
	swo := &factory.SwOpts{}
	pko := &pkcs11.PKCS11Opts{}
	ca.Config.CSP = &factory.FactoryOpts{ProviderName: "PKCS11", SwOpts: swo, Pkcs11Opts: pko}
	ca.HomeDir = ""
	err = ca.init(false)
	t.Logf("ca.init error: %v", err)
	if err == nil {
		t.Fatalf("Server init should have failed: BCCSP err")
	}

	// delete everything and start over
	// initKeyMaterial error
	os.Chdir("..")

	confDir, err = cdTmpTestDir("TestCaInit")
	if err != nil {
		t.Fatalf("failed to cd to tmp dir: %s", err)
	}
	wd2, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %s", err)
	}
	t.Log("changed to ", wd2)
	defer func() {
		err = os.RemoveAll(wd2)
		if err != nil {
			t.Fatalf("RemoveAll failed: %s", err)
		} else {
			t.Logf("Removed all: %s", wd2)
		}
	}()

	ca.Config.CSP = &factory.FactoryOpts{ProviderName: "SW", SwOpts: swo, Pkcs11Opts: pko}
	ca, err = NewCA(confDir, &cfg, &srv, true)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}
	ca.Config.CA.Keyfile = caKey
	ca.Config.CA.Certfile = caCert
	err = os.Link("../ec256-1-key.pem", caKey)
	if err != nil {
		t.Fatal("symlink error: ", err)
	}
	err = os.Link("../ec256-2-cert.pem", caCert)
	if err != nil {
		t.Fatal("symlink error: ", err)
	}
	err = ca.init(false)
	t.Logf("init err: %v", err)
	if err == nil {
		t.Fatal("Should have failed: ")
	}

	err = os.Remove(caKey)
	err = os.Remove(caCert)
	ca.Config.CA.Keyfile = ""
	ca.Config.CA.Certfile = ""
	ca.Config.DB.Datasource = ""
	ca, err = NewCA(confDir, &cfg, &srv, true)
	if err != nil {
		t.Fatal("NewCA FAILED")
	}
	err = ca.init(false)
	t.Logf("init err: %v", err)
	if err != nil {
		t.Fatal("ca init failed", err)
	}

	// initDB error
	ca.Config.LDAP.Enabled = true
	err = ca.init(false)
	t.Logf("init err: %v", err)
	if err == nil {
		t.Fatal("Should have failed: ")
	}

	// initEnrollmentSigner error
	ca.Config.LDAP.Enabled = false
	ca, err = NewCA(confDir, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA FAILED")
	}
	err = os.RemoveAll("./msp")
	if err != nil {
		t.Fatalf("os.Remove msp failed: %v", err)
	}
	err = os.Remove(caCert)
	if err != nil {
		t.Fatalf("os.Remove failed: %v", err)
	}
	err = os.Link("../rsa2048-1-key.pem", caKey)
	if err != nil {
		t.Fatal("symlink error: ", err)
	}
	err = os.Link("../rsa2048-1-cert.pem", caCert)
	if err != nil {
		t.Fatal("symlink error: ", err)
	}
	ca.Config.CA.Keyfile = caKey
	ca.Config.CA.Certfile = caCert
	err = ca.init(false)
	t.Logf("init err: %v", err)
	if err == nil {
		t.Fatal("Should have failed")
	}
}

func getTestDir(d string) (string, error) {
	td, err := ioutil.TempDir(".", d)
	if err != nil {
		return string(""), err
	}
	_, d2 := filepath.Split(td)
	return d2, nil
}

func cdTmpTestDir(name string) (string, error) {
	os.Chdir(testdir)
	tmpDir, err := getTestDir(name)
	if err != nil {
		return "", err
	}
	os.Chdir(tmpDir)
	return tmpDir, nil
}
