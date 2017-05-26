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

package util

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"math/big"

	"github.com/hyperledger/fabric/bccsp/factory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	factory.InitFactories(nil)
	os.Exit(m.Run())
}

func TestGetEnrollmentIDFromPEM(t *testing.T) {
	cert, err := ioutil.ReadFile(getPath("ec.pem"))
	if err != nil {
		t.Fatalf("TestGetEnrollmentIDFromPEM.ReadFile failed: %s", err)
	}
	_, err = GetEnrollmentIDFromPEM(cert)
	if err != nil {
		t.Fatalf("Failed to get enrollment ID from PEM: %s", err)
	}
}

func TestECCreateToken(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	bccsp := GetDefaultBCCSP()
	privKey, err := ImportBCCSPKeyFromPEM(getPath("ec-key.pem"), bccsp, true)
	if err != nil {
		t.Logf("Failed importing key %s", err)
	}
	body := []byte("request byte array")

	ECtoken, err := CreateToken(bccsp, cert, privKey, body)
	if err != nil {
		t.Fatalf("CreatToken failed: %s", err)
	}

	_, err = VerifyToken(bccsp, ECtoken, body)
	if err != nil {
		t.Fatalf("VerifyToken failed: %s", err)
	}

	_, err = VerifyToken(nil, ECtoken, body)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no instance of csp is passed")
	}

	_, err = VerifyToken(bccsp, "", body)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no EC Token is passed")
	}

	_, err = VerifyToken(bccsp, ECtoken, nil)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no EC Token is passed")
	}

	verifiedByte := []byte("TEST")
	body = append(body, verifiedByte[0])
	_, err = VerifyToken(bccsp, ECtoken, body)
	if err == nil {
		t.Fatal("VerifyToken should have failed as body was tampered")
	}

	ski, skierror := ioutil.ReadFile(getPath("ec-key.ski"))
	if skierror != nil {
		t.Fatalf("SKI File Read failed with error : %s", skierror)
	}
	ECtoken, err = CreateToken(bccsp, ski, privKey, body)
	if (err == nil) || (ECtoken != "") {
		t.Fatal("CreatToken should have failed as certificate passed is not correct")
	}
}

func TestGetX509CertFromPem(t *testing.T) {

	certBuffer, error := ioutil.ReadFile(getPath("ec.pem"))
	if error != nil {
		t.Fatalf("Certificate File Read from file failed with error : %s", error)
	}
	certificate, err := GetX509CertificateFromPEM(certBuffer)
	if err != nil {
		t.Fatalf("GetX509CertificateFromPEM failed with error : %s", err)
	}
	if certificate == nil {
		t.Fatal("Certificate cannot be nil")
	}

	skiBuffer, skiError := ioutil.ReadFile(getPath("ec-key.ski"))
	if skiError != nil {
		t.Fatalf("SKI File read failed with error : %s", skiError)
	}

	certificate, err = GetX509CertificateFromPEM(skiBuffer)
	if err == nil {
		t.Fatal("GetX509CertificateFromPEM should have failed as bytes passed was not in correct format")
	}
	if certificate != nil {
		t.Fatalf("GetX509CertificateFromPEM should have failed as bytes passed was not in correct format")
	}

}

// This test case has been removed temporarily
// as BCCSP does not have support for RSA private key import
/*
func TestRSACreateToken(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("rsa.pem"))
	privKey, _ := ioutil.ReadFile(getPath("rsa-key.pem"))
	body := []byte("request byte array")

	csp := factory.GetDefault()
	RSAtoken, err := CreateToken(csp, cert, privKey, body)
	if err != nil {
		t.Fatalf("CreatToken failed with error : %s", err)
	}

	_, err = VerifyToken(csp, RSAtoken, body)
	if err != nil {
		t.Fatalf("VerifyToken failed with error : %s", err)
	}
}
*/

func TestCreateTokenDiffKey(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	bccsp := GetDefaultBCCSP()
	privKey, _ := ImportBCCSPKeyFromPEM(getPath("rsa-key.pem"), bccsp, true)
	body := []byte("request byte array")
	_, err := CreateToken(bccsp, cert, privKey, body)
	if err == nil {
		t.Fatalf("TestCreateTokenDiffKey passed but should have failed")
	}
}

// TestCreateTokenDiffKey2 has been commeted out right now
// As there BCCSP does not have support fot RSA private Key
// import. This will be uncommented when the support is in.
/*
func TestCreateTokenDiffKey2(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("rsa.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")

	csp := factory.GetDefault()
	_, err := CreateToken(csp, cert, privKey, body)
	if err == nil {
		t.Fatalf("TestCreateTokenDiffKey2 passed but should have failed")
	}
}
*/

func TestEmptyToken(t *testing.T) {
	body := []byte("request byte array")

	csp := factory.GetDefault()
	_, err := VerifyToken(csp, "", body)
	if err == nil {
		t.Fatalf("TestEmptyToken passed but should have failed")
	}
}

func TestEmptyCert(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	body := []byte("request byte array")

	csp := factory.GetDefault()
	_, err := CreateToken(csp, cert, nil, body)
	if err == nil {
		t.Fatalf("TestEmptyCert passed but should have failed")
	}
}

func TestEmptyKey(t *testing.T) {
	bccsp := GetDefaultBCCSP()
	privKey, _ := ImportBCCSPKeyFromPEM(getPath("ec-key.pem"), bccsp, true)
	body := []byte("request byte array")
	_, err := CreateToken(bccsp, []byte(""), privKey, body)
	if err == nil {
		t.Fatalf("TestEmptyKey passed but should have failed")
	}
}

func TestEmptyBody(t *testing.T) {
	bccsp := GetDefaultBCCSP()
	privKey, _ := ImportBCCSPKeyFromPEM(getPath("ec-key.pem"), bccsp, true)
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	_, err := CreateToken(bccsp, cert, privKey, []byte(""))
	if err != nil {
		t.Fatalf("CreateToken failed: %s", err)
	}
}

func TestRandomString(t *testing.T) {
	str := RandomString(10)
	if str == "" {
		t.Fatalf("RandomString failure")
	}
}

func TestRemoveQuotes(t *testing.T) {
	str := RemoveQuotes(`"a"`)
	if str != "a" {
		t.Fatalf("TestRemoveQuotes failed")
	}
}

func TestRemoveQuotesNone(t *testing.T) {
	str := RemoveQuotes(`a`)
	if str != "a" {
		t.Fatalf("TestRemoveQuotesNone failed")
	}
}

func TestCreateHome(t *testing.T) {
	t.Log("Test Creating Home Directory")
	os.Unsetenv("COP_HOME")
	tempDir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Errorf("Failed to create temp directory [error: %s]", err)
	}
	os.Setenv("HOME", tempDir)

	dir, err := CreateClientHome()
	if err != nil {
		t.Errorf("Failed to create home directory, error: %s", err)
	}

	if _, err = os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			t.Error("Failed to create home directory")
		}
	}

	os.RemoveAll(dir)
}

func TestGetDefaultConfigFile(t *testing.T) {
	os.Unsetenv("FABRIC_CA_HOME")
	os.Unsetenv("FABRIC_CA_CLIENT_HOME")
	os.Unsetenv("FABRIC_CA_SERVER_HOME")
	os.Unsetenv("CA_CFG_PATH")

	const clientConfig = "fabric-ca-client-config.yaml"
	const serverConfig = "fabric-ca-server-config.yaml"

	os.Setenv("HOME", "/tmp")

	expected := filepath.Join("/tmp/.fabric-ca-client/", clientConfig)
	real := GetDefaultConfigFile("fabric-ca-client")
	if real != expected {
		t.Errorf("Incorrect default config path retrieved; expected %s but found %s",
			expected, real)
	}

	os.Setenv("FABRIC_CA_HOME", "/tmp")
	expected = filepath.Join("/tmp", clientConfig)
	real = GetDefaultConfigFile("fabric-ca-client")
	if real != expected {
		t.Errorf("Incorrect default config path retrieved; expected %s but found %s",
			expected, real)
	}

	expected = filepath.Join("/tmp", serverConfig)
	real = GetDefaultConfigFile("fabric-ca-server")
	if real != expected {
		t.Errorf("Incorrect default config path retrieved; expected %s but found %s",
			expected, real)
	}

	os.Setenv("FABRIC_CA_CLIENT_HOME", "/tmp/client")
	expected = filepath.Join("/tmp/client", clientConfig)
	real = GetDefaultConfigFile("fabric-ca-client")
	if real != expected {
		t.Errorf("Incorrect default config path retrieved; expected %s but found %s",
			expected, real)
	}

	os.Setenv("FABRIC_CA_SERVER_HOME", "/tmp/server")
	expected = filepath.Join("/tmp/server", serverConfig)
	real = GetDefaultConfigFile("fabric-ca-server")
	if real != expected {
		t.Errorf("Incorrect default config path retrieved; expected %s but found %s",
			expected, real)
	}
}

func TestUnmarshal(t *testing.T) {
	byteArray := []byte(`{"text":"foo"}`)
	type test struct {
		text string
	}
	var Test test
	err := Unmarshal(byteArray, &Test, "testing unmarshal")
	if err != nil {
		t.Error("Failed to unmarshal, error: ", err)
	}
}

func TestMarshal(t *testing.T) {
	var x interface{}
	_, err := Marshal(x, "testing marshal")
	if err != nil {
		t.Error("Failed to marshal, error: ", err)
	}
}

func TestReadFile(t *testing.T) {
	_, err := ReadFile("../testdata/csr.json")
	if err != nil {
		t.Error("Failed to read file, error: ", err)
	}
}

func TestWriteFile(t *testing.T) {
	testData := []byte("foo")
	err := WriteFile("../testdata/test.txt", testData, 0777)
	if err != nil {
		t.Error("Failed to write file, error: ", err)
	}
	os.Remove("../testdata/test.txt")
}

func getPath(file string) string {
	return "../testdata/" + file
}

func TestStrContained(t *testing.T) {
	strs := []string{"one", "two", "three"}
	str := "one"
	result := StrContained(str, strs)
	if result != true {
		t.Error("Should have result in true")
	}
}

func TestFileExists(t *testing.T) {
	name := "../testdata/csr.json"
	exists := FileExists(name)
	if exists == false {
		t.Error("File does not exist")
	}
	name = "better-not-exist"
	exists = FileExists(name)
	if exists == true {
		t.Error("File 'better-not-exist' should not exist")
	}
}

func TestMakeFileAbs(t *testing.T) {
	testMakeFileAbs(t, "", "", "")
	testMakeFileAbs(t, "/a/b/c", "", "/a/b/c")
	testMakeFileAbs(t, "c", "/a/b", "/a/b/c")
	testMakeFileAbs(t, "../c", "/a/b", "/a/c")
}

func TestMakeFilesAbs(t *testing.T) {
	file1 := "a"
	file2 := "a/b"
	file3 := "/a/b"
	files := []*string{&file1, &file2, &file3}
	err := MakeFileNamesAbsolute(files, "/tmp")
	if err != nil {
		t.Fatalf("MakeFilesAbsolute failed: %s", err)
	}
	if file1 != "/tmp/a" {
		t.Errorf("TestMakeFilesAbs failure: expecting /tmp/a but found %s", file1)
	}
	if file2 != "/tmp/a/b" {
		t.Errorf("TestMakeFilesAbs failure: expecting /tmp/a/b but found %s", file2)
	}
	if file3 != "/a/b" {
		t.Errorf("TestMakeFilesAbs failure: expecting /a/b but found %s", file3)
	}
}

func TestB64(t *testing.T) {
	buf := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	str := B64Encode(buf)
	buf2, err := B64Decode(str)
	if err != nil {
		t.Errorf("Failed base64 decoding standard: %s", err)
	}
	if !bytes.Equal(buf, buf2) {
		t.Error("Failed base64 decoding standard bytes aren't equal")
	}
}

func TestGetUser(t *testing.T) {
	os.Unsetenv("FABRIC_CA_CLIENT_URL")
	viper.BindEnv("url", "FABRIC_CA_CLIENT_URL")
	os.Setenv("FABRIC_CA_CLIENT_URL", "http://localhost:7054")
	_, _, err := GetUser()
	assert.Error(t, err, "Should have failed no username and password provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://:pass@localhost:7054")
	_, _, err = GetUser()
	assert.Error(t, err, "Should have failed no username provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://user:@localhost:7054")
	_, _, err = GetUser()
	assert.Error(t, err, "Should have failed no password provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://foo:bar@localhost:7054")

	user, pass, err := GetUser()
	assert.NoError(t, err)

	if user != "foo" {
		t.Error("Failed to retrieve correct username")
	}

	if pass != "bar" {
		t.Error("Failed to retrieve correct password")
	}
}

func TestStructToString(t *testing.T) {
	var obj struct {
		Name  string
		Addr  string `json:"address"`
		Pass  string `secret:"password"`
		Pass1 string `secret:"password,token"`
		Pass2 string `secret:"token,password"`
		pass3 string `secret:"token,password,basic"`
	}
	obj.Name = "foo"
	addr := "101, penn ave"
	obj.Addr = addr
	obj.Pass, obj.Pass1, obj.Pass2 = "bar", "bar", "bar"
	obj.pass3 = "bar"
	str := StructToString(&obj)
	if strings.Index(str, "bar") > 0 {
		t.Errorf("Password is not masked by the StructToString function: %s", str)
	}
	if strings.Index(str, "foo") < 0 {
		t.Errorf("Name is masked by the StructToString function: %s", str)
	}
	if strings.Index(str, addr) < 0 {
		t.Errorf("Addr is masked by the StructToString function: %s", str)
	}
}

func TestNormalizeFileList(t *testing.T) {
	var err error
	slice := []string{"file1,file2", "file3,file4"}

	slice, err = NormalizeFileList(slice, "../testdata")
	if err != nil {
		t.Error("Failed to normalize files list, error: ", err)
	}

	if !strings.Contains(slice[0], "file1") {
		t.Error("Failed to correctly normalize files list")
	}

	if strings.Contains(slice[0], "file2") {
		t.Error("Should have failed, first element should not contain 'file2'")
	}

	if !strings.Contains(slice[1], "file2") {
		t.Error("Failed to correctly normalize files list")
	}

	if !strings.Contains(slice[3], "file4") {
		t.Error("Failed to correctly normalize files list")
	}
}

func testMakeFileAbs(t *testing.T, file, dir, expect string) {
	path, err := MakeFileAbs(file, dir)
	if err != nil {
		t.Errorf("Failed to make %s absolute: %s", file, err)
	}
	// make expected path platform specific to work on Windows
	if expect != "" {
		expect, _ = filepath.Abs(expect)
	}
	if path != expect {
		t.Errorf("Absolute of file=%s with dir=%s expected %s but was %s", file, dir, expect, path)
	}
}

func TestRemoveQuotesInvalidArgs(t *testing.T) {
	res := RemoveQuotes("")
	assert.Equal(t, "", res)
}

func TestUnmarshalInvalidArgs(t *testing.T) {
	err := Unmarshal(nil, nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to unmarshal ")
}

func TestStrContainedInvalidArgs(t *testing.T) {
	res := StrContained("Hello World", nil)
	assert.False(t, res)
}

func TestGetSerialAsHex(t *testing.T) {
	res := GetSerialAsHex(big.NewInt(101))
	assert.Equal(t, "65", res)
}

func TestECPrivateKey(t *testing.T) {
	_, err := GetECPrivateKey(getPEM("../testdata/ec-key.pem", t))
	assert.NoError(t, err)
}

func TestPKCS8WrappedECPrivateKey(t *testing.T) {
	_, err := GetECPrivateKey(getPEM("../testdata/pkcs8eckey.pem", t))
	assert.NoError(t, err)
}

func TestRSAPrivateKey(t *testing.T) {
	_, err := GetRSAPrivateKey(getPEM("../testdata/rsa-key.pem", t))
	assert.NoError(t, err)
}

func TestCheckHostsInCert(t *testing.T) {
	err := CheckHostsInCert("../testdata/doesnotexist.pem", "")
	assert.Error(t, err)

	err = CheckHostsInCert("../testdata/tls_server-cert.pem", "localhost")
	assert.NoError(t, err, fmt.Sprintf("Failed to find 'localhost' for host in certificate: %s", err))

	err = CheckHostsInCert("../testdata/tls_server-cert.pem", "fakehost")
	assert.Error(t, err, "Certificate does not contain 'fakehost', should have failed")

	err = CheckHostsInCert("../testdata/root.pem", "x")
	assert.Error(t, err, "Certificate contained no host, should have failed")
}

func TestCertDuration(t *testing.T) {
	d, err := GetCertificateDurationFromFile("../testdata/ec.pem")
	assert.NoError(t, err)
	assert.True(t, d.Hours() == 43800, "Expected certificate duration of 43800h in ec.pem")
	_, err = GetCertificateDurationFromFile("bogus.pem")
	assert.Error(t, err)
}

func getPEM(file string, t *testing.T) []byte {
	buf, err := ioutil.ReadFile(file)
	assert.NoError(t, err)
	return buf
}

func TestIsSubsetOf(t *testing.T) {
	testIsSubsetOf(t, "a,b", "b,a,c", true)
	testIsSubsetOf(t, "a,b", "b,a", true)
	testIsSubsetOf(t, "a,b,c", "a,b", false)
	testIsSubsetOf(t, "a,b,c", "", false)
}

func testIsSubsetOf(t *testing.T, small, large string, expectToPass bool) {
	err := IsSubsetOf(small, large)
	if expectToPass {
		if err != nil {
			t.Errorf("IsSubsetOf('%s','%s') failed: %s", small, large, err)
		}
	} else {
		if err == nil {
			t.Errorf("IsSubsetOf('%s','%s') expected error but passed", small, large)
		}
	}
}
