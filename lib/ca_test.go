/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/mocks"
	"github.com/hyperledger/fabric-ca/lib/server/db/sqlite"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	"github.com/stretchr/testify/assert"
)

const (
	testdir               = "../testdata/"
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

var (
	configFile = serverCfgFile(testdir)
)

var cfg CAConfig
var srv Server

func TestCABadCACertificates(t *testing.T) {
	srv.levels = &dbutil.Levels{
		Identity:    1,
		Affiliation: 1,
		Certificate: 1,
	}
	mockOperationsServer := &mocks.OperationsServer{}
	fakeCounter := &metricsfakes.Counter{}
	fakeCounter.WithReturns(fakeCounter)
	mockOperationsServer.NewCounterReturns(fakeCounter)
	fakeHistogram := &metricsfakes.Histogram{}
	fakeHistogram.WithReturns(fakeHistogram)
	mockOperationsServer.NewHistogramReturns(fakeHistogram)

	srv.Operations = mockOperationsServer
	testDirClean(t)
	ca, err := newCA(configFile, &CAConfig{}, &srv, false)
	if err != nil {
		t.Fatal("newCA failed ", err)
	}
	err = ca.validateCertAndKey(noCACert, noCAkey)
	t.Log("validateCertAndKey Error: ", err)
	if err == nil {
		t.Error("Should have failed, non-CA certificate provided")
	}
	err = ca.validateCertAndKey(badUsageCert, badUsageKey)
	t.Log("validateCertAndKey Error: ", err)
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
	CAclean(ca, t)
}

func testValidDates(cert *x509.Certificate, t *testing.T) {
	err := validateDates(cert)
	t.Log("validateDates Error: ", err)
	if err == nil {
		t.Error("Should have failed, expired CA certificate provided")
	}
}

func testValidUsages(cert *x509.Certificate, t *testing.T) {
	err := validateUsage(cert, "")
	t.Log("validateUsage Error: ", err)
	if err == nil {
		t.Error("Should have failed, incorrect usage specified for certificate")
	}

	cert, err = getCertFromFile(badUsageCert)
	if err != nil {
		t.Fatal(err)
	}

	err = validateUsage(cert, "")
	t.Log("validateUsage Error: ", err)
	if assert.Error(t, err, "Should have failed, missing 'Cert Sign' key usage") {
		assert.Contains(t, err.Error(), "'cert sign' key usage is required")
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
	err := GenerateECDSATestCert()
	util.FatalError(t, err, "Failed to generate certificate for testing")
	cert, err = getCertFromFile(ecCert)
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
	ca, err := newCA(serverCfgFile(os.TempDir()), &CAConfig{}, &srv, true)
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
	CAclean(ca, t)
}

func TestCAgetUserAffiliation(t *testing.T) {
	testDirClean(t)
	ca, err := newCA(configFile, &CAConfig{}, &srv, false)
	if err != nil {
		t.Fatal("newCA failed ", err)
	}
	_, err = ca.getUserAffiliation(string(0))
	t.Log("getUserAffiliation err: ", err)
	if err == nil {
		t.Error("getUserAffiliation should have failed: bad parameter")
	}
	CAclean(ca, t)
}

func TestCAuserHasAttribute(t *testing.T) {
	testDirClean(t)
	ca, err := newCA(configFile, &CAConfig{}, &srv, false)
	if err != nil {
		t.Fatal("newCA failed ", err)
	}
	_, err = ca.userHasAttribute(string(0), string(0))
	t.Log("userHasAttribute err: ", err)
	if err == nil {
		t.Error("userHasAttribute should have failed: bad parameter")
	}
	CAclean(ca, t)
}

func TestCAgetUserAttrValue(t *testing.T) {
	testDirClean(t)
	ca, err := newCA(configFile, &CAConfig{}, &srv, false)
	if err != nil {
		t.Fatal("newCA failed: ", err)
	}
	_, err = ca.getUserAttrValue("maryjokopechne", "delmont")
	t.Log("getUserAttrValue err: ", err)
	if err == nil {
		t.Error("getUserAttrValue sould have failed: no such user")
	}
	CAclean(ca, t)
}

func TestCAaddIdentity(t *testing.T) {
	testDirClean(t)
	id := &CAConfigIdentity{
		Name: "admin",
		Pass: "adminpw",
	}

	cfg = CAConfig{}
	cfg.Registry = CAConfigRegistry{MaxEnrollments: 10}
	ca, err := newCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("newCA failed: ", err)
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
	CAclean(ca, t)
}

func TestCAinitUserRegistry(t *testing.T) {
	testDirClean(t)
	cfg = CAConfig{}
	cfg.LDAP.Enabled = true
	cfg.LDAP.URL = "ldap://CN=admin,dc=example,dc=com:adminpw@localhost:389/dc=example,dc=com"
	ca, err := newCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("newCA FAILED", err)
	}
	CAclean(ca, t)
}

func TestCAgetCaCert(t *testing.T) {
	testDirClean(t)
	os.Remove(configFile)
	cfg = CAConfig{}

	cfg.CSR = api.CSRInfo{CA: &csr.CAConfig{}}
	cfg.CSR.CA.Expiry = string(0)
	_, err := newCA(configFile, &cfg, &srv, false)
	t.Log("getCaCert error: ", err)
	if err == nil {
		t.Error("newCA should have failed")
	}

	cfg.CSR.CA.Expiry = ""
	ca, err := newCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("newCA failed ", err)
	}
	cfg.CSR.CA.Expiry = ""
	_, err = ca.getCACert()
	if err != nil {
		t.Error("getCaCert failed ", err)
	}

	ca.Config.CA.Keyfile = ecPrivKeyMatching
	ca.Config.CA.Certfile = "/"
	ca, err = newCA(configFile, &cfg, &srv, true)
	t.Log("getCaCert error: ", err)
	if err == nil {
		t.Fatal("newCA should have failed")
	}

	CAclean(ca, t)
	err = os.RemoveAll(configFile)
	if err != nil {
		t.Errorf("RemoveAll failed: %s", err)
	}
}

func TestCAinitEnrollmentSigner(t *testing.T) {
	testDirClean(t)
	cfg = CAConfig{}
	ca, err := newCA(configFile, &cfg, &srv, true)
	if err != nil {
		t.Fatal("newCA FAILED", err)
	}

	cfg.Intermediate.ParentServer.URL = "1"
	ca, err = newCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("newCA FAILED", err)
	}

	//Rely on default policy
	cfg.Signing = nil
	ca.csp = nil
	err = ca.initEnrollmentSigner()
	t.Log("ca.initEnrollmentSigner error: ", err)
	if err == nil {
		t.Error("initEnrollmentSigner should have failed")
	}
	CAclean(ca, t)
}

func TestCADBinit(t *testing.T) {
	orgwd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get cwd")
	}
	confDir, err := cdTmpTestDir("TestCADBinit")
	t.Logf("Conf dir: %s", confDir)
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
	t.Logf("serverCfgFile(confDir): %s", serverCfgFile(confDir))
	ca, err := newCA(serverCfgFile(confDir), &cfg, &srv, false)
	if ca.db != nil {
		t.Error("Create DB should have failed")
	}
}

func TestCAloadAffiliationsTableR(t *testing.T) {
	testDirClean(t)
	cfg = CAConfig{}
	ca, err := newCA(configFile, &cfg, &srv, true)
	if err != nil {
		t.Fatal("newCA FAILED", err)
	}

	//Failure to write to DB; non-valid accessor
	dbAccessor := &Accessor{}
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
	CAclean(ca, t)
}

func TestCAloadUsersTable(t *testing.T) {
	testDirClean(t)
	cfg = CAConfig{}
	u := &CAConfigIdentity{Name: "a", MaxEnrollments: -10}
	cfg.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	ca, err := newCA(configFile, &cfg, &srv, false)
	t.Log("ca.newCA error: ", err)
	if err == nil {
		t.Error("ca.newCA should have failed")
	}

	// Chase down all error paths using duplicate entries
	i := make([]interface{}, 3)
	i[1] = []string{"", "root", "root"}
	cfg.Affiliations = make(map[string]interface{}, 3)
	cfg.Affiliations["a"] = i

	// Valid registration
	err = os.Remove(testdir + dbname)
	if err != nil {
		t.Fatalf("Remove failed: %s", err)
	}
	u = &CAConfigIdentity{Name: "a", MaxEnrollments: 10}
	cfg.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	ca, err = newCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("newCA FAILED", err)
	}

	u = &CAConfigIdentity{Name: "a", MaxEnrollments: 10}
	ca.Config.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	err = ca.loadUsersTable()
	if err != nil {
		t.Error("ca.loadUsersTable failed ", err)
	}

	// Duplicate resgistration, non-error
	u = &CAConfigIdentity{Name: "a", MaxEnrollments: 10}
	ca.Config.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	err = ca.loadUsersTable()
	if err != nil {
		t.Error("ca.loadUsersTable error path should have succeeded: ", err)
	}

	// Database error (db is closed)
	u = &CAConfigIdentity{Name: "b", MaxEnrollments: 10}
	ca.Config.Registry = CAConfigRegistry{Identities: []CAConfigIdentity{*u}, MaxEnrollments: 10}
	err = ca.closeDB()
	if err != nil {
		t.Fatalf("CloseDB failed: %s", err)
	}
	err = os.Remove(testdir + dbname)
	if err != nil {
		t.Fatalf("Remove failed: %s", err)
	}
	err = ca.loadUsersTable()
	t.Log("ca.loadUsersTable error: ", err)
	if err == nil {
		t.Error("ca.loadUsersTable should have failed due to DB error ", err)
	}
	CAclean(ca, t)
}

func TestCAVerifyCertificate(t *testing.T) {
	testDirClean(t)
	cfg = CAConfig{}
	ca, err := newCA(configFile, &cfg, &srv, false)
	if err != nil {
		t.Fatal("newCA FAILED", err)
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

	err = GenerateECDSATestCert()
	util.FatalError(t, err, "Failed to generate certificate for testing")
	caCert1, err := ioutil.ReadFile("../testdata/ec_cert.pem")
	caCert2 := append(caCert1, util.RandomString(128)...)
	err = ioutil.WriteFile(filepath.Join(os.TempDir(), "ca-chainfile.pem"), caCert2, 0644)
	ca.Config.CA.Chainfile = filepath.Join(os.TempDir(), "ca-chainfile.pem")
	err = ca.VerifyCertificate(cert)
	t.Log("ca.VerifyCertificate error: ", err)
	if err == nil {
		t.Error("VerifyCertificate should have failed")
	}
	err = os.Remove(filepath.Join(os.TempDir(), "ca-chainfile.pem"))
	if err != nil {
		t.Errorf("Remove failed: %s", err)
	}

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
	CAclean(ca, t)
}

// Loads a registrar user and a non-registrar user into database. Server is started using an existing database
// with users. This test verifies that the registrar is given the new attribute "hf.Registrar.Attribute" but
// the non-registrar user is not.
func TestServerMigration(t *testing.T) {
	dir := "migrationTest"
	os.RemoveAll(dir)
	defer os.RemoveAll(dir)
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}

	sqliteDB := sqlite.NewDB(filepath.Join(dir, "fabric-ca-server.db"), "", nil)
	err = sqliteDB.Connect()
	assert.NoError(t, err, "failed to connect to database")
	db, err := sqliteDB.Create()
	assert.NoError(t, err, "failed to create database")

	util.FatalError(t, err, "Failed to create db")
	_, err = db.Exec("", "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments, level) VALUES ('registrar', '', 'user', 'org2', '[{\"name\":\"hf.Registrar.Roles\",\"value\":\"user,peer,client\"}]', '0', '-1', '0')")
	assert.NoError(t, err, "Failed to insert user 'registrar' into database")
	_, err = db.Exec("", "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments, level) VALUES ('notregistrar', '', 'user', 'org2', '[{\"name\":\"hf.Revoker\",\"value\":\"true\"}]', '0', '-1', '0')")
	assert.NoError(t, err, "Failed to insert user 'notregistrar' into database")

	server := TestGetServer2(false, rootPort, dir, "", -1, t)
	if server == nil {
		return
	}
	err = server.Start()
	util.FatalError(t, err, "Server start failed")
	defer func() {
		err = server.Stop()
		if err != nil {
			t.Errorf("Failed to stop server: %s", err)
		}
	}()

	registrar, err := server.CA.registry.GetUser("registrar", nil)
	assert.NoError(t, err, "Failed to get user")
	registrarAttr, err := registrar.GetAttribute("hf.Registrar.Attributes")
	assert.NoError(t, err, "Failed to get attribute")
	t.Logf("registrarAttr: '%+v'", registrarAttr)
	if registrarAttr.Value == "" {
		t.Error("Failed to correctly migrate user 'registrar'")
	}

	notregistrar, err := server.CA.registry.GetUser("notregistrar", nil)
	assert.NoError(t, err, "Failed to get user")
	_, err = notregistrar.GetAttribute("hf.Registrar.Attributes")
	assert.Error(t, err, "Non-registrar user should not have this attribute, failed to correctly migrate user")
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

func serverCfgFile(dir string) string {
	return path.Join(dir, "fabric-ca-server-config.yaml")
}

func cleanupTmpfiles(t *testing.T, d string) {
	err := os.RemoveAll(d) // clean up
	if err != nil {
		t.Fatal("Remove failed: ", err)
	} else {
		t.Log("Removed: ", d)
	}
}

func CAclean(ca *CA, t *testing.T) {
	if ca != nil {
		err := ca.closeDB()
		if err != nil {
			t.Error("CloseDB failed: ", err)
		}
	}
	testDirClean(t)
}

func testDirClean(t *testing.T) {
	err := os.RemoveAll(testdir + "msp")
	if err != nil {
		t.Fatal("RemoveAll failed: ", err)
	}
	err = os.RemoveAll(testdir + "ca-cert.pem")
	if err != nil {
		t.Fatal("RemoveAll failed: ", err)
	}
	err = os.RemoveAll(testdir + "ca-key.pem")
	if err != nil {
		t.Fatal("RemoveAll failed: ", err)
	}
	err = os.RemoveAll(testdir + dbname)
	if err != nil {
		t.Fatal("RemoveAll failed: ", err)
	}
	os.Remove(configFile)
}
