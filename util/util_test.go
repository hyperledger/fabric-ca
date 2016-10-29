package util

import (
	"io/ioutil"
	"testing"
)

func TestECCreateToken(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")
	ECtoken, err := CreateToken(cert, privKey, body)
	if err != nil {
		t.Fatalf("CreatToken failed: ", err)
	}
	ECverified := VerifyToken(ECtoken, body)
	if ECverified != nil {
		t.Fatalf("VerifyToken failed: ", ECverified)
	}
}

func TestRSACreateToken(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("rsa.pem"))
	privKey, _ := ioutil.ReadFile(getPath("rsa-key.pem"))
	body := []byte("request byte array")
	RSAtoken, err := CreateToken(cert, privKey, body)
	if err != nil {
		t.Fatalf("CreatToken failed: ", err)
	}
	RSAverified := VerifyToken(RSAtoken, body)
	if RSAverified != nil {
		t.Fatalf("VerifyToken failed: ", RSAverified)
	}
}

func TestCreateTokenDiffKey(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	privKey, _ := ioutil.ReadFile(getPath("rsa-key.pem"))
	body := []byte("request byte array")
	_, err := CreateToken(cert, privKey, body)
	if err == nil {
		t.Fatalf("TestCreateTokenDiffKey passed but should have failed")
	}
}

func TestCreateTokenDiffKey2(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("rsa.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")
	_, err := CreateToken(cert, privKey, body)
	if err == nil {
		t.Fatalf("TestCreateTokenDiffKey2 passed but should have failed")
	}
}

func TestEmptyToken(t *testing.T) {
	body := []byte("request byte array")
	err := VerifyToken("", body)
	if err == nil {
		t.Fatalf("TestEmptyToken passed but should have failed")
	}
}

func TestEmptyCert(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("rsa.pem"))
	body := []byte("request byte array")
	_, err := CreateToken(cert, []byte(""), body)
	if err == nil {
		t.Fatalf("TestEmptyCert passed but should have failed")
	}
}

func TestEmptyKey(t *testing.T) {
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	body := []byte("request byte array")
	_, err := CreateToken([]byte(""), privKey, body)
	if err == nil {
		t.Fatalf("TestEmptyKey passed but should have failed")
	}
}

func TestEmptyBody(t *testing.T) {
	cert, _ := ioutil.ReadFile(getPath("ec.pem"))
	privKey, _ := ioutil.ReadFile(getPath("ec-key.pem"))
	_, err := CreateToken(cert, privKey, []byte(""))
	if err != nil {
		t.Fatalf("CreateToken failed: ", err)
	}
}

func getPath(file string) string {
   return "../testdata/" + file
}
