/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TODO(mjs): So many tests that aren't. These need to be reviewed to ensure
// that the tests are driving out the correct paths and assertions as there
// are some obvious deficiencies.

func TestGetEnrollmentIDFromPEM(t *testing.T) {
	cert, err := ioutil.ReadFile(filepath.Join("testdata", "ec.pem"))
	assert.NoError(t, err)

	_, err = GetEnrollmentIDFromPEM(cert)
	assert.NoError(t, err, "failed to get enrollment ID from PEM")
}

func TestECCreateToken(t *testing.T) {
	bccsp := GetDefaultBCCSP()
	privKey, err := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "ec-key.pem"), bccsp, true)
	assert.NoError(t, err, "failed to import key")

	cert, err := ioutil.ReadFile(filepath.Join("testdata", "ec.pem"))
	assert.NoError(t, err)
	body := []byte("request byte array")

	tok, err := CreateToken(bccsp, cert, privKey, "GET", "/enroll", body)
	assert.NoError(t, err, "CreateToken failed")

	os.Setenv("FABRIC_CA_SERVER_COMPATIBILITY_MODE_V1_3", "false") // Test new token
	_, err = VerifyToken(bccsp, tok, "GET", "/enroll", body, false)
	assert.NoError(t, err, "VerifyToken failed")

	_, err = VerifyToken(nil, tok, "GET", "/enroll", body, false)
	assert.Error(t, err, "VerifyToken should have failed as no instance of CSP was provided")

	_, err = VerifyToken(bccsp, "", "GET", "/enroll", body, false)
	assert.Error(t, err, "VerifyToken should have failed as no EC token was provided")

	_, err = VerifyToken(bccsp, tok, "GET", "/enroll", nil, false)
	assert.Error(t, err, "VerifyToken should have failed as no body was provided")

	_, err = VerifyToken(bccsp, tok, "POST", "/enroll", body, false)
	assert.Error(t, err, "VerifyToken should have failed as the method was changed")

	_, err = VerifyToken(bccsp, tok, "GET", "/affiliations", body, false)
	assert.Error(t, err, "VerifyToken should have failed as the path was changed")

	_, err = VerifyToken(bccsp, tok, "GET", "/enroll", append(body, byte('T')), false)
	assert.Error(t, err, "VerifyToken should have failed as the body was changed")

	ski, err := ioutil.ReadFile(filepath.Join("testdata", "ec-key.ski"))
	assert.NoError(t, err, "failed to read ec-key.ski")

	tok, err = CreateToken(bccsp, ski, privKey, "GET", "/enroll", body)
	assert.Error(t, err, "CreateToken should have failed with non-certificate")
	assert.Equal(t, "", tok)

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
	_, _, _, err := decodeToken(token)
	assert.Error(t, err, "Decode should fail if the token has more than two parts")

	token = "x"
	_, _, _, err = decodeToken(token)
	assert.Error(t, err, "Decode should fail if the token has less than two parts")

	token = "x.y"
	_, _, _, err = decodeToken(token)
	assert.Error(t, err, "Decode should fail if the 1st part of the token is not in base64 encoded format")

	fakecert := B64Encode([]byte("hello"))
	token = fakecert + ".y"
	_, _, _, err = decodeToken(token)
	assert.Error(t, err, "Decode should fail if the 1st part of the token is not base64 bytes of a X509 cert")
}

func TestGetX509CertFromPem(t *testing.T) {
	certBuffer, err := ioutil.ReadFile(filepath.Join("testdata", "ec.pem"))
	assert.NoError(t, err)

	certificate, err := GetX509CertificateFromPEM(certBuffer)
	assert.NoError(t, err, "GetX509CertificateFromPEM failed")
	assert.NotNil(t, certificate, "certificate cannot be nil")

	skiBuffer, err := ioutil.ReadFile(filepath.Join("testdata", "ec-key.ski"))
	assert.NoError(t, err)

	certificate, err = GetX509CertificateFromPEM(skiBuffer)
	assert.Error(t, err, "GetX509CertificateFromPEM should have failed as bytes passed was not in correct format")
	assert.Nil(t, certificate, "GetX509CertificateFromPEM should have failed as bytes passed was not in correct format")
}

func TestGetX509CertsFromPem(t *testing.T) {
	certBuffer, err := ioutil.ReadFile(filepath.Join("testdata", "ec.pem"))
	assert.NoError(t, err)

	certificates, err := GetX509CertificatesFromPEM(certBuffer)
	assert.NoError(t, err, "GetX509CertificatesFromPEM failed")
	assert.NotNil(t, certificates)
	assert.Equal(t, 1, len(certificates), "GetX509CertificatesFromPEM should have returned 1 certificate")

	skiBuffer, err := ioutil.ReadFile(filepath.Join("testdata", "ec-key.ski"))
	assert.NoError(t, err)

	certificates, err = GetX509CertificatesFromPEM(skiBuffer)
	assert.Error(t, err, "GetX509CertificatesFromPEM should have failed as bytes passed was not in correct format")
	assert.Nil(t, certificates, "GetX509CertificatesFromPEM should have failed as bytes passed was not in correct format")
}

// TODO(mjs): This isn't testing what it claims to test. RSA keys cannot be
// imported so privKey is nil when CreateToken is called.

// func TestCreateTokenDiffKey(t *testing.T) {
// 	cert, _ := ioutil.ReadFile(filepath.Join("testdata", "ec.pem"))
// 	bccsp := GetDefaultBCCSP()
// 	privKey, _ := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "rsa-key.pem"), bccsp, true)
// 	body := []byte("request byte array")
// 	_, err := CreateToken(bccsp, cert, privKey, "POST", "/enroll", body)
// 	if err == nil {
// 		t.Fatalf("TestCreateTokenDiffKey passed but should have failed")
// 	}
// }

func TestEmptyToken(t *testing.T) {
	csp := factory.GetDefault()
	_, err := VerifyToken(csp, "", "POST", "/enroll", []byte("request-body"), true)
	assert.Error(t, err, "verification should fail with an empty token")
}

func TestEmptyCert(t *testing.T) {
	cert, err := ioutil.ReadFile(filepath.Join("testdata", "ec.pem"))
	assert.NoError(t, err)

	csp := factory.GetDefault()
	_, err = CreateToken(csp, cert, nil, "POST", "/enroll", []byte("request body"))
	assert.Error(t, err, "CreateToken should have failed with nil key")
}

func TestEmptyKey(t *testing.T) {
	bccsp := GetDefaultBCCSP()
	privKey, err := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "ec-key.pem"), bccsp, true)
	assert.NoError(t, err)

	_, err = CreateToken(bccsp, []byte(""), privKey, "POST", "/enroll", []byte("request body"))
	assert.Error(t, err, "CreateToken should have failed with empty certificate")
}

func TestEmptyBody(t *testing.T) {
	bccsp := GetDefaultBCCSP()
	privKey, err := ImportBCCSPKeyFromPEM(filepath.Join("testdata", "ec-key.pem"), bccsp, true)
	assert.NoError(t, err)
	cert, err := ioutil.ReadFile(filepath.Join("testdata", "ec.pem"))
	assert.NoError(t, err)

	_, err = CreateToken(bccsp, cert, privKey, "POST", "/enroll", []byte(""))
	assert.NoError(t, err, "create token should succeed with empty body")
}

func TestRandomString(t *testing.T) {
	for i := 0; i <= 10; i++ {
		str := RandomString(i)
		assert.Equal(t, i, len(str))
	}
}

func TestCreateHome(t *testing.T) {
	tempDir := t.TempDir()

	os.Setenv("HOME", tempDir)
	dir, err := CreateClientHome()
	assert.NoError(t, err, "Failed to create home directory, error: %s")
	assert.Equal(t, filepath.Join(tempDir, ".fabric-ca-client"), dir)
	assert.DirExists(t, dir, "client home directory was not created")
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
	actual := GetDefaultConfigFile("fabric-ca-client")
	assert.Equal(t, expected, actual, "incorrect default config path")

	os.Setenv("FABRIC_CA_HOME", "/tmp")
	expected = filepath.Join("/tmp", clientConfig)
	actual = GetDefaultConfigFile("fabric-ca-client")
	assert.Equal(t, expected, actual, "incorrect default config path")

	expected = filepath.Join("/tmp", serverConfig)
	actual = GetDefaultConfigFile("fabric-ca-server")
	assert.Equal(t, expected, actual, "incorrect default config path")

	os.Setenv("FABRIC_CA_CLIENT_HOME", "/tmp/client")
	expected = filepath.Join("/tmp/client", clientConfig)
	actual = GetDefaultConfigFile("fabric-ca-client")
	assert.Equal(t, expected, actual, "incorrect default config path")

	os.Setenv("FABRIC_CA_SERVER_HOME", "/tmp/server")
	expected = filepath.Join("/tmp/server", serverConfig)
	actual = GetDefaultConfigFile("fabric-ca-server")
	assert.Equal(t, expected, actual, "incorrect default config path")
}

// TODO(mjs): Move the implementation to the consumer(s). The majority of the
// users are in the client pacakge and all the code does is annotate error
// messages and hide the fact that the serialization format is JSON.
// Oh, and the test doesn't even test the error wrapping aspect...
func TestUnmarshal(t *testing.T) {
	byteArray := []byte(`{"text":"foo"}`)
	var test struct {
		Text string
	}
	err := Unmarshal(byteArray, &test, "testing unmarshal")
	assert.NoError(t, err, "failed to unmarshal")
	assert.Equal(t, "foo", test.Text)
}

func TestUnmarshalInvalidArgs(t *testing.T) {
	err := Unmarshal(nil, nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to unmarshal ")
}

// TODO(mjs): Move the implementation to the consumer(s). The majority of the
// users are in the 'lib' pacakge and all the code does is annotate error
// messages and hide the fact that the serialization format is JSON.
// Oh, and the test doesn't even test the error wrapping aspect...
func TestMarshal(t *testing.T) {
	var x interface{}
	_, err := Marshal(x, "testing marshal")
	assert.NoError(t, err, "failed to marshal")
}

// TODO(mjs): Get rid of this. It's literally a call to ioutil.ReadFile.
func TestReadFile(t *testing.T) {
	_, err := ReadFile(filepath.Join("testdata", "csr.json"))
	assert.NoError(t, err, "failed to read file")
}

func TestWriteFile(t *testing.T) {
	testdir := t.TempDir()

	testData := []byte("foo")
	err := WriteFile(filepath.Join(testdir, "test.txt"), testData, 0777)
	assert.NoError(t, err)

	readOnlyDir := filepath.Join(testdir, "readonlydir")
	err = os.MkdirAll(readOnlyDir, 4444)
	assert.NoError(t, err, "failed to create read only directory")
	err = WriteFile(filepath.Join(readOnlyDir, "test/test.txt"), testData, 0777)
	assert.Error(t, err, "Should fail to create 'test' directory as the parent directory is read only")
}

func TestFileExists(t *testing.T) {
	name := filepath.Join("testdata", "csr.json")
	exists := FileExists(name)
	assert.True(t, exists, "%s should be an existing file", name)

	exists = FileExists("better-not-exist")
	assert.False(t, exists, "better-not-exist should not be an existing file")
}

func testMakeFileAbs(t *testing.T, file, dir, expect string) {
	path, err := MakeFileAbs(file, dir)
	assert.NoError(t, err, "failed to make %s absolute", file)
	assert.Equal(t, expect, path, "unexpected absolute path for file %q in directory %q", file, dir)
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
	assert.NoError(t, err, "MakeFileNamesAbsolute failed")

	assert.Equal(t, "/tmp/a", file1)
	assert.Equal(t, "/tmp/a/b", file2)
	assert.Equal(t, "/a/b", file3)
}

func TestB64(t *testing.T) {
	// FIXME(mjs): And this tests the standard library...
	buf := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	str := B64Encode(buf)
	buf2, err := B64Decode(str)
	assert.NoError(t, err, "failed base64 decoding")
	assert.Equal(t, buf, buf2)
}

func TestGetUser(t *testing.T) {
	v := viper.New()
	os.Unsetenv("FABRIC_CA_CLIENT_URL")
	err := v.BindEnv("url", "FABRIC_CA_CLIENT_URL")
	assert.NoError(t, err)

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://localhost:7054")
	_, _, err = GetUser(v)
	assert.Error(t, err, "Should have failed no username and password provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://:pass@localhost:7054")
	_, _, err = GetUser(v)
	assert.Error(t, err, "Should have failed no username provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://user:@localhost:7054")
	_, _, err = GetUser(v)
	assert.Error(t, err, "Should have failed no password provided")

	os.Setenv("FABRIC_CA_CLIENT_URL", "http://foo:bar@localhost:7054")
	user, pass, err := GetUser(v)
	assert.NoError(t, err)
	assert.Equal(t, "foo", user, "unexpected username")
	assert.Equal(t, "bar", pass, "unexpected password")
}

type masked struct {
	Name string `mask:"username"`
	Addr string `json:"address"`
	Pass string `mask:"password"`
	URL  string `mask:"url"`
	ID   int    `mask:"url"`
}

func (cc masked) String() string {
	return StructToString(&cc)
}

func TestStructToString(t *testing.T) {
	obj := masked{
		Name: "foo",
		Addr: "101, penn ave",
		Pass: "bar",
		URL:  "http://bang:bazzword@localhost:7054",
	}
	str := StructToString(&obj)
	assert.NotContains(t, str, "bar", "password is not masked")
	assert.NotContains(t, str, "foo", "name is not masked")
	assert.Contains(t, str, obj.Addr, "address should not be masked")
	assert.NotContains(t, str, "bang", "user from url is not masked in the output")
	assert.NotContains(t, str, "bazzword", "password from url is not masked in the output")

	type registry struct{ Identities []masked }
	type config struct{ Registry registry }
	caConfig := config{
		Registry: registry{
			Identities: []masked{
				{
					Name: "foo",
					Pass: "foopwd",
					Addr: "user",
					URL:  "http://foo:foopwd@localhost:7054",
					ID:   2,
				},
				{
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
	assert.NotContains(t, caConfig.Registry.Identities[0].String(), "foopwd", "Identity password is not masked in the output")
	assert.NotContains(t, caConfig.Registry.Identities[1].String(), "barpwd", "Identity password is not masked in the output")
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
	slice, err := NormalizeFileList(slice, "testdata")
	assert.NoError(t, err, "failed to normalize files list")
	assert.Len(t, slice, 6, "Invalid slice length")

	dataDir, err := filepath.Abs("testdata")
	assert.NoError(t, err)
	for i := range slice {
		assert.Equal(t, dataDir, filepath.Dir(slice[i]))
		assert.Equal(t, fmt.Sprintf("file%d", i), filepath.Base(slice[i]))
	}
}

func TestGetSerialAsHex(t *testing.T) {
	res := GetSerialAsHex(big.NewInt(101))
	assert.Equal(t, "65", res)
}

func TestECPrivateKey(t *testing.T) {
	_, err := GetECPrivateKey(getPEM(filepath.Join("testdata", "ec-key.pem"), t))
	assert.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 256)
	assert.NoError(t, err, "failed to create RSA key")
	encodedPK, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	assert.NoError(t, err, "failed to marshal RSA private key")

	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = GetECPrivateKey(pemEncodedPK)
	assert.Error(t, err)

	_, err = GetECPrivateKey([]byte("hello"))
	assert.Error(t, err)

	_, err = GetECPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("hello")}))
	assert.Error(t, err)
}

func TestPKCS8WrappedECPrivateKey(t *testing.T) {
	_, err := GetECPrivateKey(getPEM(filepath.Join("testdata", "pkcs8eckey.pem"), t))
	assert.NoError(t, err)
}

func TestRSAPrivateKey(t *testing.T) {
	_, err := GetRSAPrivateKey([]byte("hello"))
	assert.Error(t, err)

	_, err = GetRSAPrivateKey(getPEM(filepath.Join("testdata", "rsa-key.pem"), t))
	assert.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 256)
	assert.NoError(t, err, "failed to create RSA key")
	encodedPK, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	assert.NoError(t, err, "failed to marshal RSA private key")

	pemEncodedPK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = GetRSAPrivateKey(pemEncodedPK)
	assert.NoError(t, err)

	_, err = GetRSAPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("hello")}))
	assert.Error(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err, "failed to generate P256 key")
	encodedPK, err = x509.MarshalPKCS8PrivateKey(ecdsaKey)
	assert.NoError(t, err, "failed to marshal P256 private key")

	pemEncodedPK = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPK})
	_, err = GetRSAPrivateKey(pemEncodedPK)
	assert.Error(t, err, "treating P56 key as RSA private key should fail")
}

func TestCheckHostsInCert(t *testing.T) {
	err := CheckHostsInCert("testdata/doesnotexist.pem", "")
	assert.Error(t, err) // TODO(mjs): clearly any error will do

	err = CheckHostsInCert(filepath.Join("testdata", "tls_server-cert.pem"), "localhost")
	assert.NoError(t, err, "failed to find 'localhost' in certificate")

	err = CheckHostsInCert("testdata/tls_server-cert.pem", "localhost", "fakehost")
	assert.Error(t, err, "certificate does not contain 'fakehost', should have failed")

	err = CheckHostsInCert("testdata/root.pem", "x")
	assert.Error(t, err, "certificate contained no host, should have failed")
}

func TestCertDuration(t *testing.T) {
	d, err := GetCertificateDurationFromFile(filepath.Join("testdata", "ec.pem"))
	assert.NoError(t, err)
	assert.EqualValues(t, 43800, d.Hours(), "Expected certificate duration of 43800h in ec.pem")

	_, err = GetCertificateDurationFromFile("bogus.pem")
	assert.Error(t, err) // TODO(mjs): clearly any error will do
}

func TestRead(t *testing.T) {
	// Test with a buffer that is too small to fit data
	buf := make([]byte, 10)
	_, err := Read(strings.NewReader("this-is-longer-than-ten-bytes"), buf)
	assert.Error(t, err, "should have failed with too much data for buffer")

	// Test with a buffer that is big enough to fit data
	buf = make([]byte, 20)
	data, err := Read(strings.NewReader("short-string"), buf)
	assert.NoError(t, err, "read should have been successful")
	assert.Equal(t, "short-string", string(data), "the read data does not match the source")

	// Test with a buffer with exact size of data
	buf = make([]byte, 2)
	data, err = Read(strings.NewReader("hi"), buf)
	assert.NoError(t, err, "read should have been successful")
	assert.Equal(t, "hi", string(data), "the read data does not match the source")
}

func getPEM(file string, t *testing.T) []byte {
	buf, err := ioutil.ReadFile(file)
	assert.NoError(t, err)
	return buf
}

func TestHostname(t *testing.T) {
	host := Hostname()
	assert.NotEqual(t, "", host, "Hostname should not be empty")
}

func TestHTTPRequestToString(t *testing.T) {
	url := "http://localhost:7054"
	reqBody := "Hello"
	req, err := http.NewRequest("POST", url, strings.NewReader(reqBody))
	assert.NoError(t, err, "failed to create http.Request")

	reqStr := HTTPRequestToString(req)
	assert.Contains(t, reqStr, url)
	assert.Contains(t, reqStr, "POST")
	assert.Contains(t, reqStr, reqBody)
}

func TestValidateAndReturnAbsConf(t *testing.T) {
	var err error
	var filename, homeDir string

	filename, _, err = ValidateAndReturnAbsConf("/tmp/test.yaml", "/tmp/homeDir", "fabric-ca-client")
	assert.NoError(t, err, "Should not have errored out, this is a valid configuration")
	assert.Equal(t, "/tmp/test.yaml", filename, "failed to get correct path for configuration file")

	filename, homeDir, err = ValidateAndReturnAbsConf("", "testdata/tmp", "fabric-ca-client")
	assert.NoError(t, err, "should not have failed with a valid configuration")

	homeDirAbs, err := filepath.Abs("testdata/tmp")
	assert.NoError(t, err)
	assert.Equal(t, homeDirAbs, homeDir, "failed to get correct path for home directory")
	assert.Equal(t, filepath.Join(homeDirAbs, "fabric-ca-client-config.yaml"), filename)

	// Test with no home directory set
	filename, _, err = ValidateAndReturnAbsConf("/tmp/test.yaml", "", "fabric-ca-client")
	assert.NoError(t, err, "Should not have errored out, this is a valid configuration")
	assert.Equal(t, "/tmp/test.yaml", filename, "failed to get correct path for configuration file")

	filename, homeDir, err = ValidateAndReturnAbsConf("testdata/tmp/test.yaml", "", "fabric-ca-client")
	assert.NoError(t, err, "should not have failed with a valid configuration")
	assert.Equal(t, homeDirAbs, homeDir, "failed to get correct path for home directory")
	assert.Equal(t, filepath.Join(homeDirAbs, "test.yaml"), filename, "failed to get correct path for configuration file")
}

func TestListContains(t *testing.T) {
	list := "peer, client,orderer, *"
	found := ListContains(list, "*")
	assert.Equal(t, found, true)

	list = "peer, client,orderer"
	found = ListContains(list, "*")
	assert.Equal(t, found, false)
}
