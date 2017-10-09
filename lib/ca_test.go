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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/pkcs11"
	"github.com/stretchr/testify/assert"
)

const (
	testdir               = "../testdata/"
	configFile            = testdir + "fabric-ca-server-config.yaml"
	dbname                = "fabric-ca-server.db"
	badcert               = "../testdata/expiredcert.pem"
	dsacert               = "../testdata/dsa-cert.pem"
	lowbitcert            = "../testdata/lowbitcert.pem"
	ecPrivKeyNotMatching  = "../testdata/ec-key.pem"
	ecCert                = "../testdata/ec_cert.pem"
	ecPrivKeyMatching     = "../testdata/ec_key.pem"
	rsacert               = "../testdata/rsa.pem"
	rsaPrivKeyNotMatching = "../testdata/rsa2048-1-key.pem"
	backDated             = "../testdata/unRipeCaEc256-cert.pem"
	badUsageCert          = "../testdata/tls_client-cert.pem"
	badUsageKey           = "../testdata/tls_client-key.pem"
	noUsageCert           = "../testdata/noKeyUsage.cert.pem"
	noUsageKey            = "../testdata/noKeyUsage.key.pem"
	noCACert              = "../testdata/caFalse.cert.pem"
	noCAkey               = "../testdata/caFalse.key.pem"
	caCert                = "ca-cert.pem"
	caKey                 = "ca-key.pem"
	caPort                = "7054"
)

var cfg CAConfig
var srv Server

func TestCABadCACertificates(t *testing.T) {
	ca, err := NewCA(configFile, &CAConfig{}, &srv, false)
	err = ca.validateCert(noCACert, noCAkey)
	t.Log("validateCert Error: ", err)
	if err == nil {
		t.Error("Should have failed, non-CA certificate provided")
	}
	err = ca.validateCert(badUsageCert, badUsageKey)
	t.Log("validateCert Error: ", err)
	if err == nil {
		t.Error("Should have failed, incorrect keyusage")
	}

	cert, err := getCertFromFile(noCACert)
	if err != nil {
		t.Fatal(err)
	}
	testValidCA(cert, t)

	cert, err = getCertFromFile(backDated)
	if err != nil {
		t.Fatal(err)
	}
	testValidDates(cert, t)

	cert, err = getCertFromFile(badcert)
	if err != nil {
		t.Fatal(err)
	}
	testValidDates(cert, t)
	testValidKeyType(cert, t)
	testValidKeySize(cert, t)
	testValidMatchingKeys(cert, t)
	testValidUsages(cert, t)
	CAclean()
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

	cert, err = getCertFromFile(badUsageCert)
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
		t.Error("Error occured during validation of a supported key type: ", err)
	}

	cert, err = getCertFromFile(dsacert)
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
		t.Error("Failed to pass a ceritificate with valid key size: ", err)
	}

	cert, err = getCertFromFile(lowbitcert)
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
	cert, err := getCertFromFile(ecCert)
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

	cert, err = getCertFromFile(rsacert)
	if err != nil {
		t.Fatal(err)
	}

	err = validateMatchingKeys(cert, rsaPrivKeyNotMatching)
	t.Log("validateMatchingKeys Error: ", err)
	if err == nil {
		t.Error("Should have failed, public key and private key do not match")
	}

	err = validateMatchingKeys(cert, ecPrivKeyNotMatching)
	t.Log("validateMatchingKeys Error: ", err)
	if err == nil {
		t.Error("Should have failed, public key and private key do not match")
	}

	err = validateMatchingKeys(cert, string(0))
	t.Log("validateMatchingKeys Error: ", err)
	if err == nil {
		t.Error("Should have failed to read bad file")
	}

}

func TestCAInit(t *testing.T) {
	orgwd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd: ", err)
	}
	confDir, err := cdTmpTestDir("TestCAInit")
	t.Log("confDir: ", confDir)
	if err != nil {
		t.Fatal("failed to cd to tmp dir: ", err)
	}
	defer func() {
		err = os.Chdir(orgwd)
		if err != nil {
			t.Fatalf("failed to cd to %v: %s", orgwd, err)
		}
	}()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd: ", err)
	}
	t.Log("Working dir", wd)
	defer cleanupTmpfiles(t, wd)

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
	os.Chdir(orgwd)

	confDir, err = cdTmpTestDir("TestCAInit")
	if err != nil {
		t.Fatal("failed to cd to tmp dir: ", err)
	}
	wd2, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd: ", err)
	}
	t.Log("changed directory to ", wd2)
	defer cleanupTmpfiles(t, wd2)

	ca.Config.CSP = &factory.FactoryOpts{ProviderName: "SW", SwOpts: swo, Pkcs11Opts: pko}
	ca, err = NewCA(confDir, &cfg, &srv, true)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}
	ca.Config.CA.Keyfile = caKey
	ca.Config.CA.Certfile = caCert
	err = CopyFile("../ec256-1-key.pem", caKey)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	err = CopyFile("../ec256-2-cert.pem", caCert)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	err = ca.init(false)
	t.Log("init err: ", err)
	if err == nil {
		t.Error("Should have failed")
	}

	err = os.Remove(caKey)
	err = os.Remove(caCert)
	ca.Config.CA.Keyfile = ""
	ca.Config.CA.Certfile = ""
	ca.Config.DB.Datasource = ""
	ca, err = NewCA(confDir, &cfg, &srv, true)
	if err != nil {
		t.Fatal("NewCA FAILED: ", err)
	}

	err = ca.init(false)
	if err != nil {
		t.Fatal("ca init failed", err)
	}

	// initUserRegistry error
	ca.Config.LDAP.Enabled = true
	err = ca.initUserRegistry()
	t.Log("init err: ", err)
	if err == nil {
		t.Fatal("initUserRegistry should have failed")
	}

	// initEnrollmentSigner error
	ca.Config.LDAP.Enabled = false
	ca, err = NewCA(confDir, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA FAILED")
	}
	err = os.RemoveAll("./msp")
	if err != nil {
		t.Fatal("os.Remove msp failed: ", err)
	}
	err = os.Remove(caCert)
	if err != nil {
		t.Fatal("os.Remove failed: ", err)
	}
	err = CopyFile("../rsa2048-1-key.pem", caKey)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	err = CopyFile("../rsa2048-1-cert.pem", caCert)
	if err != nil {
		t.Fatal("Failed to copy file: ", err)
	}
	ca.Config.CA.Keyfile = caKey
	ca.Config.CA.Certfile = caCert
	err = ca.init(false)
	t.Log("init err: ", err)
	if err == nil {
		t.Fatal("init should have failed")
	}
}

// Tests String method of CAConfigDB
func TestCAConfigDBStringer(t *testing.T) {
	dbconfig := CAConfigDB{
		Type:       "postgres",
		Datasource: "dbname=mypostgres host=127.0.0.1 port=8888 user=admin password=admin sslmode=disable",
	}
	str := fmt.Sprintf("%+v", dbconfig) // String method of CAConfigDB is called here
	t.Logf("Stringified postgres CAConfigDB: %s", str)
	assert.Contains(t, str, "user=****", "Username is not masked in the datasource URL")
	assert.Contains(t, str, "password=****", "Password is not masked in the datasource URL")

	dbconfig.Datasource = "dbname=mypostgres host=127.0.0.1 port=8888 password=admin sslmode=disable user=admin"
	str = fmt.Sprintf("%+v", dbconfig) // String method of CAConfigDB is called here
	t.Logf("Stringified postgres CAConfigDB: %s", str)
	assert.Contains(t, str, "user=****", "Username is not masked in the datasource URL")
	assert.Contains(t, str, "password=****", "Password is not masked in the datasource URL")

	dbconfig.Datasource = "dbname=cadb password=adminpwd host=127.0.0.1 port=8888 user=cadb sslmode=disable"
	str = fmt.Sprintf("%+v", dbconfig) // String method of CAConfigDB is called here
	t.Logf("Stringified postgres CAConfigDB: %s", str)
	assert.Contains(t, str, "user=****", "Username is not masked in the datasource URL")
	assert.Contains(t, str, "password=****", "Password is not masked in the datasource URL")

	dbconfig = CAConfigDB{
		Type:       "mysql",
		Datasource: "root:rootpw@tcp(localhost:8888)/mysqldb?parseTime=true",
	}
	str = fmt.Sprintf("%+v", dbconfig)
	t.Logf("Stringified mysql CAConfigDB: %s", str)
	assert.NotContains(t, str, "root", "Username is not masked in the datasource URL")
	assert.NotContains(t, str, "rootpw", "Password is not masked in the datasource URL")
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

func TestCAParseDuration(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Log("Successfully recovered ", r)
		} else {
			t.Error("parseDuration should have failed")
		}
	}()

	parseDuration("9999999999999999999")
}

func TestCAwriteFile(t *testing.T) {
	err := writeFile("/"+string(0)+"/", make([]byte, 1), 0777)
	t.Log("writeFile err: ", err)
	if err == nil {
		t.Fatal("Should have failed: ")
	}
	err = writeFile(string(0), make([]byte, 1), 0777)
	t.Log("writeFile err: ", err)
	if err == nil {
		t.Fatal("Should have failed: ")
	}
}

func TestCAloadCNFromEnrollmentInfo(t *testing.T) {
	ca, err := NewCA("/tmp", &CAConfig{}, &srv, true)
	_, err = ca.loadCNFromEnrollmentInfo(string(0))
	t.Log("loadCNFromEnrollmentInfo err: ", err)
	if err == nil {
		t.Error("Should have failed: ")
	}
	_, err = ca.loadCNFromEnrollmentInfo(ecPrivKeyMatching)
	t.Log("loadCNFromEnrollmentInfo err: ", err)
	if err == nil {
		t.Error("Should have failed: ")
	}
	CAclean()
}

func TestCAgetUserAffiliation(t *testing.T) {
	ca, err := NewCA(configFile, &CAConfig{}, &srv, false)
	if err != nil {
		t.Fatal("NewCa failed ", err)
	}
	_, err = ca.getUserAffiliation(string(0))
	t.Log("getUserAffiliation err: ", err)
	if err == nil {
		t.Error("getUserAffiliation should have failed: bad parameter")
	}
	CAclean()
}

func TestCAuserHasAttribute(t *testing.T) {
	ca, err := NewCA(configFile, &CAConfig{}, &srv, false)
	if err != nil {
		t.Fatal("NewCa failed ", err)
	}
	_, err = ca.userHasAttribute(string(0), string(0))
	t.Log("userHasAttribute err: ", err)
	if err == nil {
		t.Error("userHasAttribute should have failed: bad parameter")
	}
	CAclean()
}

func TestCAgetUserAttrValue(t *testing.T) {
	ca, err := NewCA(configFile, &CAConfig{}, &srv, false)
	if err != nil {
		t.Fatal("NewCa failed: ", err)
	}
	_, err = ca.getUserAttrValue("maryjokopechne", "delmont")
	t.Log("getUserAttrValue err: ", err)
	if err == nil {
		t.Error("getUserAttrValue sould have failed: no such user")
	}
	CAclean()
}

func TestCAaddIdentity(t *testing.T) {
	id := &CAConfigIdentity{
		Name: "admin",
		Pass: "adminpw",
	}

	cfg = CAConfig{}
	cfg.Registry = CAConfigRegistry{MaxEnrollments: 10}
	ca, err := NewCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCa failed: ", err)
	}
	err = ca.addIdentity(id, true)
	t.Log("ca.addIdentity err: ", err)
	if err != nil {
		t.Error("ca.addIdentity failed: ", err)
	}
	err = ca.addIdentity(id, true)
	t.Log("ca.addIdentity err: ", err)
	if err == nil {
		t.Error("getUserAttrValue sould have failed: duplicate id")
	}
	CAclean()
}

func TestCAinitUserRegistry(t *testing.T) {
	os.Remove(testdir + dbname)
	os.Remove(configFile)
	cfg = CAConfig{}
	cfg.LDAP.Enabled = true
	cfg.LDAP.URL = "ldap://CN=admin,dc=example,dc=com:adminpw@localhost:389/dc=example,dc=com"
	_, err := NewCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}
	os.Remove(testdir + dbname)
}

func TestCAgetCaCert(t *testing.T) {
	CAclean()
	os.Remove(configFile)
	cfg = CAConfig{}

	cfg.CSR = api.CSRInfo{CA: &csr.CAConfig{}}
	cfg.CSR.CA.Expiry = string(0)
	_, err := NewCA(configFile, &cfg, &srv, false)
	t.Log("getCaCert error: ", err)
	if err == nil {
		t.Error("NewCA should have failed")
	}

	cfg.CSR.CA.Expiry = ""
	ca, err := NewCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA failed ", err)
	}
	cfg.CSR.CA.Expiry = ""
	_, err = ca.getCACert()
	if err != nil {
		t.Error("getCaCert failed ", err)
	}

	ca.Config.CA.Keyfile = ecPrivKeyMatching
	ca.Config.CA.Certfile = "/"
	ca, err = NewCA(configFile, &cfg, &srv, true)
	t.Log("getCaCert error: ", err)
	if err == nil {
		t.Fatal("NewCA should have failed")
	}

	CAclean()
	os.Remove(configFile)
}

func TestCAinitEnrollmentSigner(t *testing.T) {
	os.Remove(testdir + dbname)
	os.Remove(configFile)
	cfg = CAConfig{}
	ca, err := NewCA(configFile, &cfg, &srv, true)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}

	cfg.Intermediate.ParentServer.URL = "1"
	ca, err = NewCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}

	//Rely on default policy
	cfg.Signing = nil
	ca.csp = nil
	err = ca.initEnrollmentSigner()
	t.Log("ca.initEnrollmentSigner error: ", err)
	if err == nil {
		t.Error("initEnrollmentSigner should have failed")
	}
	os.Remove(testdir + dbname)
}

func TestCADBinit(t *testing.T) {
	orgwd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd")
	}
	confDir, err := cdTmpTestDir("TestCADBinit")
	defer func() {
		err = os.Chdir(orgwd)
		if err != nil {
			t.Fatalf("failed to cd to %v: %s", orgwd, err)
		}
	}()
	wd, err := os.Getwd()
	defer cleanupTmpfiles(t, wd)

	cfg = CAConfig{}
	cfg.DB = CAConfigDB{Datasource: "root:mysql@" + util.RandomString(237)}
	ca, err := NewCA(confDir, &cfg, &srv, false)
	if ca.db != nil {
		t.Error("Create DB shold have failed")
	}
}

func TestCAloadAffiliationsTableR(t *testing.T) {
	os.Remove(testdir + dbname)
	os.Remove(configFile)
	cfg = CAConfig{}
	ca, err := NewCA(configFile, &cfg, &srv, true)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}

	//Failure to write to DB; non-valid accessor
	dbAccessor := new(Accessor)
	ca.registry = dbAccessor

	i := make([]interface{}, 3)
	i[1] = []string{"", "root", "root"}
	ca.Config.Affiliations = make(map[string]interface{}, 3)
	ca.Config.Affiliations["a"] = i
	err = ca.loadAffiliationsTable()
	t.Log("ca.loadAffiliationsTable error: ", err)
	if err == nil {
		t.Error("ca.loadAffiliationsTableR should have failed ", err)
	}
	err = ca.loadAffiliationsTableR(i[1], "")
	t.Log("ca.loadAffiliationsTableR error: ", err)
	if err == nil {
		t.Error("ca.loadAffiliationsTableR should have failed ", err)
	}
	err = ca.loadAffiliationsTableR(i, "root")
	t.Log("ca.loadAffiliationsTableR error: ", err)
	if err == nil {
		t.Error("ca.loadAffiliationsTableR should have failed ", err)
	}

	os.Remove(testdir + dbname)
}

func TestCAloadUsersTable(t *testing.T) {
	CAclean()
	os.Remove(configFile)
	cfg = CAConfig{}
	u := &CAConfigIdentity{Name: "a", MaxEnrollments: -10}
	cfg.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	_, err := NewCA(configFile, &cfg, &srv, false)
	t.Log("ca.NewCA error: ", err)
	if err == nil {
		t.Error("ca.NewCA should have failed")
	}

	//Chase down all error paths using duplicate entries
	i := make([]interface{}, 3)
	i[1] = []string{"", "root", "root"}
	cfg.Affiliations = make(map[string]interface{}, 3)
	cfg.Affiliations["a"] = i

	//Valid registration
	os.Remove(testdir + dbname)
	u = &CAConfigIdentity{Name: "a", MaxEnrollments: 10}
	cfg.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	ca, err := NewCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}

	u = &CAConfigIdentity{Name: "a", MaxEnrollments: 10}
	ca.Config.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	err = ca.loadUsersTable()
	if err != nil {
		t.Error("ca.loadUsersTable failed ", err)
	}

	//Duplicate resgistration, non-error
	u = &CAConfigIdentity{Name: "a", MaxEnrollments: 10}
	ca.Config.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	err = ca.loadUsersTable()
	if err != nil {
		t.Error("ca.loadUsersTable error path should have succeeded: ", err)
	}

	//Database error
	u = &CAConfigIdentity{Name: "b", MaxEnrollments: 10}
	ca.Config.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	os.Remove(testdir + dbname)
	err = ca.loadUsersTable()
	t.Log("ca.loadUsersTable error: ", err)
	if err == nil {
		t.Error("ca.loadUsersTable should have failed due to DB error ", err)
	}
	os.Remove(testdir + dbname)
}

func TestCAVerifyCertificate(t *testing.T) {
	CAclean()
	os.Remove(configFile)
	cfg = CAConfig{}
	ca, err := NewCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("NewCA FAILED", err)
	}

	cert, err := getCertFromFile(noCACert)
	if err != nil {
		t.Fatal(err)
	}

	ca.Config.CA.Keyfile = caKey
	ca.Config.CA.Certfile = caCert
	ca.Config.CA.Chainfile = "../testdata/empty.json"
	err = ca.VerifyCertificate(cert)
	t.Log("ca.VerifyCertificate error: ", err)
	if err == nil {
		t.Error("VerifyCertificate should have failed")
	}

	ca.Config.CA.Chainfile = "../testdata/crl.pem"
	err = ca.VerifyCertificate(cert)
	t.Log("ca.VerifyCertificate error: ", err)
	if err == nil {
		t.Error("VerifyCertificate should have failed")
	}

	caCert1, err := ioutil.ReadFile("../testdata/ec_cert.pem")
	caCert2 := append(caCert1, util.RandomString(128)...)
	err = ioutil.WriteFile("/tmp/ca-chainfile.pem", caCert2, 0644)
	ca.Config.CA.Chainfile = "/tmp/ca-chainfile.pem"
	err = ca.VerifyCertificate(cert)
	t.Log("ca.VerifyCertificate error: ", err)
	if err == nil {
		t.Error("VerifyCertificate should have failed")
	}
	os.Remove("/tmp/ca-chainfile.pem")

	ca.Config.CA.Chainfile = "doesNotExist"
	ca.Config.CA.Certfile = "doesNotExist"
	ca.Config.Intermediate.ParentServer.URL = "http://127.0.0.1:" + caPort
	err = ca.VerifyCertificate(cert)
	t.Log("ca.VerifyCertificate error: ", err)
	if err == nil {
		t.Error("VerifyCertificate should have failed")
	}
	ca.Config.CA.Chainfile = noUsageCert
	err = ca.VerifyCertificate(cert)
	t.Log("ca.VerifyCertificate error: ", err)
	if err == nil {
		t.Error("VerifyCertificate should have failed")
	}

	CAclean()
}

func getCertFromFile(f string) (*x509.Certificate, error) {
	p, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("read of %s failed", f)
	}
	c, err := util.GetX509CertificateFromPEM(p)
	if err != nil {
		return nil, fmt.Errorf("decode of %s failed", f)
	}
	return c, nil
}

func cleanupTmpfiles(t *testing.T, d string) {
	err := os.RemoveAll(d) // clean up
	if err != nil {
		t.Fatal("Remove failed: ", err)
	} else {
		t.Log("Removed: ", d)
	}
}

func CAclean() {
	os.RemoveAll(testdir + "msp")
	os.Remove(testdir + "ca-cert.pem")
	os.Remove(testdir + "ca-key.pem")
	os.Remove(testdir + dbname)
}
