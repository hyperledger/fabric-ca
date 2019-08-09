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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperledger/fabric/bccsp/factory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

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

	ECtoken, err := CreateToken(bccsp, cert, privKey, "GET", "/enroll", body)
	if err != nil {
		t.Fatalf("CreatToken failed: %s", err)
	}

	os.Setenv("FABRIC_CA_SERVER_COMPATIBILITY_MODE_V1_3", "false") // Test new token
	_, err = VerifyToken(bccsp, ECtoken, "GET", "/enroll", body, false)
	if err != nil {
		t.Fatalf("VerifyToken failed: %s", err)
	}

	_, err = VerifyToken(nil, ECtoken, "GET", "/enroll", body, false)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no instance of csp is passed")
	}

	_, err = VerifyToken(bccsp, "", "GET", "/enroll", body, false)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no EC Token is passed")
	}

	_, err = VerifyToken(bccsp, ECtoken, "GET", "/enroll", nil, false)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no body is passed")
	}

	_, err = VerifyToken(bccsp, ECtoken, "POST", "/enroll", nil, false)
	if err == nil {
		t.Fatal("VerifyToken should have failed as method was tampered")
	}

	_, err = VerifyToken(bccsp, ECtoken, "GET", "/affiliations", nil, false)
	if err == nil {
		t.Fatal("VerifyToken should have failed as path was tampered")
	}

	verifiedByte := []byte("TEST")
	body = append(body, verifiedByte[0])
	_, err = VerifyToken(bccsp, ECtoken, "GET", "/enroll", body, false)
	if err == nil {
		t.Fatal("VerifyToken should have failed as body was tampered")
	}

	ski, skierror := ioutil.ReadFile(getPath("ec-key.ski"))
	if skierror != nil {
		t.Fatalf("SKI File Read failed with error : %s", skierror)
	}
	ECtoken, err = CreateToken(bccsp, ski, privKey, "GET", "/enroll", body)
	if (err == nil) || (ECtoken != "") {
		t.Fatal("CreatToken should have failed as certificate passed is not correct")
	}

	// With comptability mode disabled, using old token should fail
	b64Cert := B64Encode(cert)
	payload := B64Encode(body) + "." + b64Cert
	oldToken, err := genECDSAToken(bccsp, privKey, b64Cert, payload)
	FatalError(t, err, "Failed to create token")
	_, err = VerifyToken(bccsp, oldToken, "GET", "/enroll", body, false)
	assert.Error(t, err)

	// Test that by default with no environment variable set, the old token is considered valid
	os.Unsetenv("FABRIC_CA_SERVER_COMPATIBILITY_MODE_V1_3")
	_, err = VerifyToken(bccsp, oldToken, "GET", "/enroll", body, true)
	assert.NoError(t, err, "Failed to verify token using old token type")
}

func TestDecodeToken(t *testing.T) {
	token := "x.y.z"
	_, _, _, err := DecodeToken(token)
	assert.Error(t, err, "Decode should fail if the token has more than two parts")

	token = "x"
	_, _, _, err = DecodeToken(token)
	assert.Error(t, err, "Decode should fail if the token has less than two parts")

	token = "x.y"
	_, _, _, err = DecodeToken(token)
	assert.Error(t, err, "Decode should fail if the 1st part of the token is not in base64 encoded format")

	fakecert := B64Encode([]byte("hello"))
	token = fakecert + ".y"
	_, _, _, err = DecodeToken(token)
	assert.Error(t, err, "Decode should fail if the 1st part of the token is not base64 bytes of a X509 cert")
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

func TestGetX509CertsFromPem(t *testing.T) {
	certBuffer, error := ioutil.ReadFile(getPath("ec.pem"))
	if error != nil {
		t.Fatalf("Certificate File Read from file failed with error : %s", error)
	}
	certificates, err := GetX509CertificatesFromPEM(certBuffer)
	assert.NoError(t, err, "GetX509CertificatesFromPEM failed")
	assert.NotNil(t, certificates)
	assert.Equal(t, 1, len(certificates), "GetX509CertificatesFromPEM should have returned 1 certificate")

	skiBuffer, skiError := ioutil.ReadFile(getPath("ec-key.ski"))
	if skiError != nil {
		t.Fatalf("SKI File read failed with error : %s", skiError)
	}

	certificates, err = GetX509CertificatesFromPEM(skiBuffer)
	if err == nil {
		t.Fatal("GetX509CertificatesFromPEM should have failed as bytes passed was not in correct format")
	}
	if certificates != nil {
		t.Fatalf("GetX509CertificatesFromPEM should have failed as bytes passed was not in correct format")
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
	_, err := CreateToken(bccsp, cert, privKey, "POST", "/enroll", body)
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
	_, err := VerifyToken(csp, "", "POST", "/enroll", body, true)
	if err == nil {
		t.Fatalf("TestEmptyToken passed but should have failed")
	}
}

func TestEmptyCert(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	body := []byte("request byte array")

	csp := factory.GetDefault()
	_, err := CreateToken(csp, cert, nil, "POST", "/enroll", body)
	if err == nil {
		t.Fatalf("TestEmptyCert passed but should have failed")
	}
}

func TestEmptyKey(t *testing.T) {
	bccsp := GetDefaultBCCSP()
	privKey, _ := ImportBCCSPKeyFromPEM(getPath("ec-key.pem"), bccsp, true)
	body := []byte("request byte array")
	_, err := CreateToken(bccsp, []byte(""), privKey, "POST", "/enroll", body)
	if err == nil {
		t.Fatalf("TestEmptyKey passed but should have failed")
	}
}

func TestEmptyBody(t *testing.T) {
	bccsp := GetDefaultBCCSP()
	privKey, _ := ImportBCCSPKeyFromPEM(getPath("ec-key.pem"), bccsp, true)
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	_, err := CreateToken(bccsp, cert, privKey, "POST", "/enroll", []byte(""))
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
	testdir, err := ioutil.TempDir(".", "writefiletest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %s", err.Error())
	}
	defer os.RemoveAll(testdir)
	testData := []byte("foo")
	err = WriteFile(path.Join(testdir, "test.txt"), testData, 0777)
	assert.NoError(t, err)
	readOnlyDir := path.Join(testdir, "readonlydir")
	err = os.MkdirAll(readOnlyDir, 4444)
	if err != nil {
		t.Fatalf("Failed to create directory: %s", err.Error())
	}
	err = WriteFile(path.Join(readOnlyDir, "test/test.txt"), testData, 0777)
	assert.Error(t, err, "Should fail to create 'test' directory as the parent directory is read only")
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
	_, _, err := GetUser(viper.GetViper())
	assert.Error(t, err, "Should have failed no username and password provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://:pass@localhost:7054")
	_, _, err = GetUser(viper.GetViper())
	assert.Error(t, err, "Should have failed no username provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://user:@localhost:7054")
	_, _, err = GetUser(viper.GetViper())
	assert.Error(t, err, "Should have failed no password provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://foo:bar@localhost:7054")

	user, pass, err := GetUser(viper.GetViper())
	assert.NoError(t, err)

	if user != "foo" {
		t.Error("Failed to retrieve correct username")
	}

	if pass != "bar" {
		t.Error("Failed to retrieve correct password")
	}
}

type configID struct {
	Name string `mask:"username"`
	Addr string `json:"address"`
	Pass string `mask:"password"`
	URL  string `mask:"url"`
	ID   int    `mask:"url"`
}

func (cc configID) String() string {
	return StructToString(&cc)
}

func TestStructToString(t *testing.T) {
	var obj configID
	obj.Name = "foo"
	addr := "101, penn ave"
	obj.Addr = addr
	obj.Pass = "bar"
	str := StructToString(&obj)
	if strings.Index(str, "bar") > 0 {
		t.Errorf("Password is not masked by the StructToString function: %s", str)
	}
	if strings.Index(str, "foo") > 0 {
		t.Errorf("Name is not masked by the StructToString function: %s", str)
	}
	if strings.Index(str, addr) < 0 {
		t.Errorf("Addr is masked by the StructToString function: %s", str)
	}

	type registry struct {
		MaxEnrollments int
		Identities     []configID
	}
	type config struct {
		Registry     registry
		Affiliations map[string]interface{}
	}
	affiliations := map[string]interface{}{"org1": nil}
	caConfig := config{
		Affiliations: affiliations,
		Registry: registry{
			MaxEnrollments: -1,
			Identities: []configID{
				configID{
					Name: "foo",
					Pass: "foopwd",
					Addr: "user",
					URL:  "http://foo:foopwd@localhost:7054",
					ID:   2,
				},
				configID{
					Name: "bar",
					Pass: "barpwd",
					Addr: "user",
					URL:  "ldap://foo:foopwd@localhost:7054",
					ID:   3,
				},
			},
		},
	}
	caConfigStr := fmt.Sprintf("caConfig=%+v", caConfig)
	assert.NotContains(t, caConfigStr, "foopwd", "Identity password is not masked in the output")
	assert.NotContains(t, caConfigStr, "barpwd", "Identity password is not masked in the output")
	idStr := fmt.Sprintf("Identity[0]=%+v", caConfig.Registry.Identities[0])
	assert.NotContains(t, idStr, "foopwd", "Identity password is not masked in the output")
	idStr = fmt.Sprintf("Identity[1]=%+v", &caConfig.Registry.Identities[1])
	assert.NotContains(t, idStr, "barpwd", "Identity password is not masked in the output")
}

func TestNormalizeStringSlice(t *testing.T) {
	var tests = []struct {
		slice    []string
		expected []string
	}{
		{
			slice:    []string{"string1"},
			expected: []string{"string1"},
		},
		{
			slice:    []string{" string1"},
			expected: []string{"string1"},
		},
		{
			slice:    []string{" string1   "},
			expected: []string{"string1"},
		},
		{
			slice:    []string{" string1   "},
			expected: []string{"string1"},
		},
		{
			slice:    []string{"string1", "string2"},
			expected: []string{"string1", "string2"},
		},
		{
			slice:    []string{"string1", "   string2"},
			expected: []string{"string1", "string2"},
		},
	}

	for _, test := range tests {
		actual := NormalizeStringSlice(test.slice)
		assert.Equal(t, test.expected, actual)
	}
}

// Test file list with multiple and single entries both with and without brackets
func TestNormalizeFileList(t *testing.T) {
	slice := []string{"[file0,file1]", "file2,file3", "file4", "[file5]"}
	slice, err := NormalizeFileList(slice, "../testdata")
	if err != nil {
		t.Fatalf("Failed to normalize files list, error: %s", err)
	}
	assert.Equal(t, 6, len(slice), "Invalid slice length")
	for i := range slice {
		if !strings.HasSuffix(slice[i], fmt.Sprintf("file%d", i)) {
			t.Errorf("Failed to normalize files list for element %d; found '%s'", i, slice[i])
		}
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

	rsaKey, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		t.Fatalf("Failed to create rsa key: %s", err.Error())
	}
	encodedPK, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA private key: %s", err.Error())
	}

	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = GetECPrivateKey(pemEncodedPK)
	assert.Error(t, err)

	_, err = GetECPrivateKey([]byte("hello"))
	assert.Error(t, err)

	_, err = GetECPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("hello")}))
	assert.Error(t, err)
}

func TestPKCS8WrappedECPrivateKey(t *testing.T) {
	_, err := GetECPrivateKey(getPEM("../testdata/pkcs8eckey.pem", t))
	assert.NoError(t, err)
}

func TestRSAPrivateKey(t *testing.T) {
	_, err := GetRSAPrivateKey([]byte("hello"))
	assert.Error(t, err)

	_, err = GetRSAPrivateKey(getPEM("../testdata/rsa-key.pem", t))
	assert.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		t.Fatalf("Failed to create rsa key: %s", err.Error())
	}
	encodedPK, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA private key: %s", err.Error())
	}

	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = GetRSAPrivateKey(pemEncodedPK)
	assert.NoError(t, err)

	_, err = GetRSAPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("hello")}))
	assert.Error(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to create rsa key: %s", err.Error())
	}
	encodedPK, err = x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA private key: %s", err.Error())
	}

	pemEncodedPK = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = GetRSAPrivateKey(pemEncodedPK)
	assert.Error(t, err)
}

func TestCheckHostsInCert(t *testing.T) {
	err := CheckHostsInCert("../testdata/doesnotexist.pem", "")
	assert.Error(t, err)

	err = CheckHostsInCert("../testdata/tls_server-cert.pem", "localhost")
	assert.NoError(t, err, fmt.Sprintf("Failed to find 'localhost' for host in certificate: %s", err))

	err = CheckHostsInCert("../testdata/tls_server-cert.pem", "localhost", "fakehost")
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

type MyReader struct {
	buf                   []byte
	maxPerRead, bytesRead int
}

func (r *MyReader) Read(data []byte) (int, error) {
	if r.bytesRead >= len(r.buf) {
		return 0, io.EOF
	}
	buf := r.buf[r.bytesRead:]
	count := 0
	for i, v := range buf {
		if i >= len(data) || count > r.maxPerRead {
			break
		}
		data[i] = v
		count++
	}
	r.bytesRead = r.bytesRead + count
	return count, nil
}

func TestRead(t *testing.T) {
	myReader := MyReader{
		buf:        []byte("123456789012345"),
		maxPerRead: 6,
	}

	// Test with a buffer that is too small to fit data
	buf := make([]byte, 10)
	data, err := Read(&myReader, buf)
	assert.Error(t, err, "Should have errored, the data passed is bigger than the buffer")

	// Test with a buffer that is big enough to fit data
	buf = make([]byte, 25)
	myReader.bytesRead = 0
	data, err = Read(&myReader, buf)
	if assert.NoError(t, err, fmt.Sprintf("Error occured during read: %s", err)) {
		if string(data) != string(myReader.buf) {
			t.Error("The data returned does not match")
		}
	}

	// Test with a buffer with exact size of data
	buf = make([]byte, len(myReader.buf))
	myReader.bytesRead = 0
	data, err = Read(&myReader, buf)
	if assert.NoError(t, err, fmt.Sprintf("Error occured during exact size read: %s", err)) {
		if string(data) != string(myReader.buf) {
			t.Error("The data returned does not match")
		}
	}
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

func TestHostname(t *testing.T) {
	host := Hostname()
	assert.NotEqual(t, "", host, "Hostname should not be empty")
}

func TestHTTPRequestToString(t *testing.T) {
	url := "http://localhost:7054"
	reqBody := "Hello"
	req, err := http.NewRequest("POST", url, strings.NewReader(reqBody))
	if err != nil {
		t.Errorf("Failed to create a request: %s", err)
	} else {
		reqStr := HTTPRequestToString(req)
		assert.Contains(t, reqStr, url)
		assert.Contains(t, reqStr, "POST")
		assert.Contains(t, reqStr, reqBody)
	}
}

func TestValidateAndReturnAbsConf(t *testing.T) {
	var err error
	var filename, homeDir string

	filename, _, err = ValidateAndReturnAbsConf("/tmp/test.yaml", "/tmp/homeDir", "fabric-ca-client")
	assert.NoError(t, err, "Should not have errored out, this is a valid configuration")

	if filename != "/tmp/test.yaml" {
		t.Error("Failed to get correct path for configuration file")
	}

	filename, homeDir, err = ValidateAndReturnAbsConf("", "../testdata/tmp", "fabric-ca-client")
	assert.NoError(t, err, "Should not have errored out, this is a valid configuration")

	homeDirAbs, err := filepath.Abs("../testdata/tmp")
	if err != nil {
		t.Fatal("Error occured getting absolute path: ", err)
	}

	if homeDir != homeDirAbs {
		t.Error("Failed to get correct path for home directory")
	}

	if filename != filepath.Join(homeDirAbs, "fabric-ca-client-config.yaml") {
		t.Error("Failed to get correct path for configuration file")
	}

	// Test with no home directory set
	filename, _, err = ValidateAndReturnAbsConf("/tmp/test.yaml", "", "fabric-ca-client")
	assert.NoError(t, err, "Should not have errored out, this is a valid configuration")

	if filename != "/tmp/test.yaml" {
		t.Error("Failed to get correct path for configuration file")
	}

	filename, homeDir, err = ValidateAndReturnAbsConf("../testdata/tmp/test.yaml", "", "fabric-ca-client")
	assert.NoError(t, err, "Should not have errored out, this is a valid configuration")

	homeDirAbs, err = filepath.Abs("../testdata/tmp")
	if err != nil {
		t.Fatal("Error occured getting absolute path: ", err)
	}

	if homeDir != homeDirAbs {
		t.Error("Failed to get correct path for home directory")
	}

	if filename != filepath.Join(homeDirAbs, "test.yaml") {
		t.Error("Failed to get correct path for configuration file")
	}
}

func TestListContains(t *testing.T) {
	list := "peer, client,orderer, *"
	found := ListContains(list, "*")
	assert.Equal(t, found, true)

	list = "peer, client,orderer"
	found = ListContains(list, "*")
	assert.Equal(t, found, false)
}
