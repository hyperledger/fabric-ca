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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperledger/fabric/bccsp/factory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
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
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")

	csp := factory.GetDefault()
	ECtoken, err := CreateToken(csp, cert, privKey, body)
	if err != nil {
		t.Fatalf("CreatToken failed: %s", err)
	}

	_, err = VerifyToken(csp, ECtoken, body)
	if err != nil {
		t.Fatalf("VerifyToken failed: %s", err)
	}

	_, err = VerifyToken(nil, ECtoken, body)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no instance of csp is passed")
	}

	_, err = VerifyToken(csp, "", body)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no EC Token is passed")
	}

	_, err = VerifyToken(csp, ECtoken, nil)
	if err == nil {
		t.Fatal("VerifyToken should have failed as no EC Token is passed")
	}

	verifiedByte := []byte("TEST")
	body = append(body, verifiedByte[0])
	_, err = VerifyToken(csp, ECtoken, body)
	if err == nil {
		t.Fatal("VerifyToken should have failed as body was tampered")
	}

	ski, skierror := ioutil.ReadFile(getPath("ec-key.ski"))
	if skierror != nil {
		t.Fatalf("SKI File Read failed with error : %s", skierror)
	}
	ECtoken, err = CreateToken(csp, ski, privKey, body)
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
	privKey, _ := ioutil.ReadFile(getPath("rsa-key.pem"))
	body := []byte("request byte array")

	csp := factory.GetDefault()
	_, err := CreateToken(csp, cert, privKey, body)
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
	_, err := CreateToken(csp, cert, []byte(""), body)
	if err == nil {
		t.Fatalf("TestEmptyCert passed but should have failed")
	}
}

func TestEmptyKey(t *testing.T) {
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")

	csp := factory.GetDefault()
	_, err := CreateToken(csp, []byte(""), privKey, body)
	if err == nil {
		t.Fatalf("TestEmptyKey passed but should have failed")
	}
}

func TestEmptyBody(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))

	csp := factory.GetDefault()
	_, err := CreateToken(csp, cert, privKey, []byte(""))
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
	makeFileAbs(t, "", "", "")
	makeFileAbs(t, "/a/b/c", "", "/a/b/c")
	makeFileAbs(t, "c", "/a/b", "/a/b/c")
	makeFileAbs(t, "../c", "/a/b", "/a/c")
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
	os.Setenv("FABRIC_CA_CLIENT_URL", "http://foo:bar@localhost:7054")

	user, pass, err := GetUser()
	if err != nil {
		t.Error(err)
	}

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

func makeFileAbs(t *testing.T, file, dir, expect string) {
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
