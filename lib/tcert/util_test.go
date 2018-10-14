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
	"crypto/rand"
	"io/ioutil"
	"math/big"
	"testing"
)

func TestGenNumber(t *testing.T) {
	num, _ := GenNumber(big.NewInt(20))
	if num == nil {
		t.Fatal("Failed in GenNumber")
	}
}

func TestECCertificate(t *testing.T) {
	publicKeyBuff, err := ioutil.ReadFile("../../testdata/ec.pem")
	if err != nil {
		t.Fatal("Cannot read EC Certificate from file system")
	}
	_, err = GetCertificate(publicKeyBuff)
	if err != nil {
		t.Fatalf("Cannot create EC Certificate \t [%v]", err)
	}
}

func TestCBCPKCS7EncryptCBCPKCS7Decrypt(t *testing.T) {

	// Note: The purpose of this test is not to test AES-256 in CBC mode's strength
	// ... but rather to verify the code wrapping/unwrapping the cipher.
	key := make([]byte, AESKeyLength)
	rand.Reader.Read(key)

	var ptext = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := CBCPKCS7Encrypt(key, ptext)
	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, encErr)
	}

	decrypted, dErr := CBCPKCS7Decrypt(key, encrypted)
	if dErr != nil {
		t.Fatalf("Error decrypting the encrypted '%s': %v", ptext, dErr)
	}

	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Decrypt( Encrypt( ptext ) ) != ptext: Ciphertext decryption with the same key must result in the original plaintext!")
	}

}

func TestPreKey(t *testing.T) {
	rootKey := CreateRootPreKey()
	if len(rootKey) == 0 {
		t.Fatal("Root Key Cannot be generated")
	}

}

func TestSerialNumber(t *testing.T) {
	publicKeyBuff, err := ioutil.ReadFile("../../testdata/ec.pem")
	if err != nil {
		t.Fatal("Cannot read EC Certificate from file system")
	}
	_, err = GetCertitificateSerialNumber(publicKeyBuff)

	if err != nil {
		t.Fatalf("Cannot create EC Certificate \t [%v]", err)
	}

	publicKeyBuff, err = ioutil.ReadFile("../../testdata/expiredcert.pem")
	if err != nil {
		t.Fatal("Cannot read Certificate from file system")
	}
	_, err = GetCertitificateSerialNumber(publicKeyBuff)
	t.Logf("GetCertitificateSerialNumber error %v", err)
	if err == nil {
		t.Fatal("GetCertitificateSerialNumber should have failed reading non-certificate")
	}
}

func TestGetBadCertificate(t *testing.T) {
	// Wrong file type
	buf, err := ioutil.ReadFile("../../testdata/server-config.json")
	if err != nil {
		t.Error("Cannot read certificate from file system")
	}
	_, err = GetCertificate([]byte(buf))
	t.Logf("GetCertitificate error %v", err)
	if err == nil {
		t.Error("Should have failed since file is json")
	}

	// pem Cert Expired
	buf, err = ioutil.ReadFile("../../testdata/expiredcert.pem")
	if err != nil {
		t.Error("Cannot read certificate from file system")
	}
	_, err = GetCertificate([]byte(buf))
	t.Logf("GetCertitificate error %v", err)
	if err == nil {
		t.Error("Should have failed since certificate is expired")
	}

	// der Cert Expired
	buf, err = ioutil.ReadFile("../../testdata/expiredcert.der")
	if err != nil {
		t.Error("Cannot read certificate from file system")
	}
	_, err = GetCertificate([]byte(buf))
	t.Logf("GetCertitificate error %v", err)
	if err == nil {
		t.Error("Should have failed since certificate is expired")
	}
}

func TestGenerateUUID(t *testing.T) {
	_, err := GenerateIntUUID()
	if err != nil {
		t.Errorf("GenerateIntUUID failed: %s", err)
	}
}

func TestDerToPem(t *testing.T) {

	buf, err := ioutil.ReadFile("../../testdata/ecTest.der")
	if err != nil {
		t.Fatalf("Cannot read Certificate in DER format: %s", err)
	}
	cert := ConvertDERToPEM(buf, "CERTIFICATE")
	if cert == nil {
		t.Fatal("Failed to ConvertDERToPEM")
	}
}

func TestGetPrivateKey(t *testing.T) {
	// PKCS1 EC
	_, err := LoadKey("../../testdata/ec-key.pem")
	if err != nil {
		t.Errorf("Cannot load PKCS1 EC Key: %v", err)
	}

	// PKCS1 RSA
	_, err = LoadKey("../../testdata/rsa-key.pem")
	if err != nil {
		t.Errorf("Cannot load PKCS1 RSA Key: %v", err)
	}

	// PKCS8 EC
	_, err = LoadKey("../../testdata/pkcs8eckey.pem")
	if err != nil {
		t.Errorf("Cannot load PKCS8 key: %v", err)
	}

	// DER
	_, err = LoadKey("../../testdata/ecTest.der")
	t.Logf("LoadKey error %v", err)
	if err == nil {
		t.Errorf("LoadKey should have failed loading DER")
	}

	// non-existent file
	_, err = LoadKey("/tmp/xxxxxxxxxxxxxxxxxxxxx.pem")
	t.Logf("LoadKey error %v", err)
	if err == nil {
		t.Errorf("LoadKey should have failed loading non-existent file")
	}

	// non-key file
	_, err = LoadKey("../../testdata/dsa-cert.pem")
	t.Logf("LoadKey error %v", err)
	if err == nil {
		t.Errorf("LoadKey should have failed loading dsa cert file")
	}

	// encrypted key file
	_, err = LoadKey("../../testdata/dsa-key.pem")
	t.Logf("LoadKey error %v", err)
	if err == nil {
		t.Errorf("LoadKey should have failed loading encrypted dsa key file")
	}
}

func TestCBCEncrypt(t *testing.T) {
	// only 16, 24 and 32 are valid key lengths
	_, err := CBCPKCS7Encrypt(make([]byte, 31), make([]byte, 0))
	t.Logf("CBCPKCS7Encrypt error:  %v", err)
	if err == nil {
		t.Errorf("CBCPKCS7Encrypt should have failed with invalid key size")
	}

	_, err = CBCPKCS7Encrypt(make([]byte, 0), make([]byte, 0))
	t.Logf("CBCPKCS7Encrypt error:  %v", err)
	if err == nil {
		t.Errorf("CBCPKCS7Encrypt should have failed with invalid key size")
	}

	_, err = CBCPKCS7Encrypt(make([]byte, 24), make([]byte, 0))
	if err != nil {
		t.Errorf("CBCPKCS7Encrypt failed with AES-128, %v", err)
	}

	_, err = CBCPKCS7Encrypt(make([]byte, 16), make([]byte, 0))
	if err != nil {
		t.Errorf("CBCPKCS7Encrypt failed with AES-192, %v", err)
	}

	_, err = CBCPKCS7Encrypt(make([]byte, 32), make([]byte, 0))
	if err != nil {
		t.Errorf("CBCPKCS7Encrypt failed with AES-256, %v", err)
	}
}

func TestCBCPKCS7Decrypt(t *testing.T) {
	// only 16, 24 and 32 are valid key lengths
	_, err := CBCPKCS7Decrypt(make([]byte, 31), make([]byte, 16))
	t.Logf("CBCPKCS7Decrypt error:  %v", err)
	if err == nil {
		t.Errorf("CBCPKCS7Decrypt should have failed: invalid key size")
	}

	_, err = CBCPKCS7Decrypt(make([]byte, 0), make([]byte, 16))
	t.Logf("CBCPKCS7Decrypt error:  %v", err)
	if err == nil {
		t.Errorf("CBCPKCS7Decrypt should have failed: invalid key size")
	}

	// invalid ciphertext
	_, err = CBCPKCS7Decrypt(make([]byte, 24), make([]byte, 0))
	t.Logf("CBCPKCS7Decrypt error:  %v", err)
	if err == nil {
		t.Errorf("CBCPKCS7Decrypt should have failed: cipher text size < aes.BlockSize")
	}

	_, err = CBCPKCS7Decrypt(make([]byte, 16), make([]byte, 31))
	t.Logf("CBCPKCS7Decrypt error:  %v", err)
	if err == nil {
		t.Errorf("CBCPKCS7Decrypt should have failed: cipher_text_size%%aes.BlockSize != 0")
	}

	_, err = CBCPKCS7Decrypt(make([]byte, 32), make([]byte, 32))
	t.Logf("CBCPKCS7Decrypt error:  %v", err)
	if err == nil {
		t.Errorf("CBCPKCS7Decrypt should have failed: invalid padding")
	}
}
