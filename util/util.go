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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	cop "github.com/hyperledger/fabric-cop/api"
	"github.com/jmoiron/sqlx"
)

var rnd = mrand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

//ECDSASignature forms the structure for R and S value for ECDSA
type ECDSASignature struct {
	R, S *big.Int
}

// RandomString returns a random string
func RandomString(n int) string {
	b := make([]byte, n)

	for i, cache, remain := n-1, rnd.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rnd.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// RemoveQuotes removes outer quotes from a string if necessary
func RemoveQuotes(str string) string {
	if str == "" {
		return str
	}
	if (strings.HasPrefix(str, "'") && strings.HasSuffix(str, "'")) ||
		(strings.HasPrefix(str, "\"") && strings.HasSuffix(str, "\"")) {
		str = str[1 : len(str)-1]
	}
	return str
}

// ReadFile reads a file
func ReadFile(file string) ([]byte, cop.Error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		log.Errorf("failure reading file '%s': %s", file, err)
		return nil, cop.WrapError(err, cop.ReadFileError, "failed reading file at %s", file)
	}
	return bytes, nil
}

// WriteFile writes a file
func WriteFile(file string, buf []byte, perm os.FileMode) cop.Error {
	err := ioutil.WriteFile(file, buf, perm)
	if err != nil {
		log.Errorf("failure writing file '%s': %s", file, err)
		return cop.WrapError(err, cop.WriteFileError, "failed reading file at %s", file)
	}
	return nil
}

// FileExists checks to see if a file exists
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Marshal to bytes
func Marshal(from interface{}, what string) ([]byte, cop.Error) {
	buf, err := json.Marshal(from)
	if err != nil {
		log.Errorf("failure unmarshalling '%s': %s", what, err)
		return nil, cop.WrapError(err, cop.MarshallError, "error marshalling %s", what)
	}
	return buf, nil
}

// Unmarshal from bytes
func Unmarshal(from []byte, to interface{}, what string) cop.Error {
	err := json.Unmarshal(from, to)
	if err != nil {
		log.Errorf("failure unmarshalling '%s': %s", what, err)
		return cop.WrapError(err, cop.UnmarshallError, "error unmarshalling %s", what)
	}
	return nil
}

// DERCertToPEM converts DER to PEM format
func DERCertToPEM(der []byte) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		},
	)
}

// CreateToken creates a JWT-like token.
// In a normal JWT token, the format of the token created is:
//      <algorithm,claims,signature>
// where each part is base64-encoded string separated by a period.
// In this JWT-like token, there are two differences:
// 1) the claims section is a certificate, so the format is:
//      <certificate,signature>
// 2) the signature uses the private key associated with the certificate,
//    and the signature is across both the certificate and the "body" argument,
//    which is the body of an HTTP request, though could be any arbitrary bytes.
// @param cert The pem-encoded certificate
// @param key The pem-encoded key
// @param body The body of an HTTP request
func CreateToken(cert []byte, key []byte, body []byte) (string, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return "Failed to generate token", errors.New("Error in decoding x509 cert given PEM-encoded cert")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "Failed to generate token", errors.New("Error in parsing x509 cert given Block Bytes")
	}
	publicKey := x509Cert.PublicKey

	var token string
	var tokenerr error

	switch publicKey.(type) {
	case *rsa.PublicKey:
		token, tokenerr = GenRSAToken(cert, key, body)
		if tokenerr != nil {
			return "Failed to generate token", errors.New(tokenerr.Error())
		}
	case *ecdsa.PublicKey:
		token, tokenerr = GenECDSAToken(cert, key, body)
		if tokenerr != nil {
			return "Failed to generate token", errors.New(tokenerr.Error())
		}
	}
	return token, nil
}

//GenRSAToken signs the http body and cert with RSA using RSA private key
func GenRSAToken(cert []byte, key []byte, body []byte) (string, error) {
	privKey, err := GetRSAPrivateKey(key)
	if err != nil {
		return "Failed to generate RSA token", errors.New("Expecting RSA private key from PEM-encoded key to verify x509 cert: " + err.Error())
	}
	b64body := B64Encode(body)
	b64cert := B64Encode(cert)
	bodyAndcert := b64body + "." + b64cert
	hash := sha512.New384()
	hash.Write([]byte(bodyAndcert))
	h := hash.Sum(nil)
	RSAsignature, signerr := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA384, h[:])
	if signerr != nil {
		return "Error in RSA signing", errors.New("rsa.SignPKCS1v15 failed to generate signature: " + signerr.Error())
	}
	b64sig := B64Encode(RSAsignature)
	token := b64cert + "." + b64sig

	return token, nil
}

//GenECDSAToken signs the http body and cert with ECDSA using EC private key
func GenECDSAToken(cert []byte, key []byte, body []byte) (string, error) {
	privKey, err := GetECPrivateKey(key)
	if err != nil {
		return "Failed to generate ECDSA token", errors.New("Expecting EC private key from PEM-encoded key to verify x509 cert: " + err.Error())
	}
	b64body := B64Encode(body)
	b64cert := B64Encode(cert)
	bodyAndcert := b64body + "." + b64cert
	hash := sha512.New384()
	hash.Write([]byte(bodyAndcert))
	h := hash.Sum(nil)
	r, s, signerr := ecdsa.Sign(rand.Reader, privKey, h)
	if signerr != nil {
		return "Error in ECDSA signing", errors.New("ecdsa.Sign failed to generate values R and S")
	}
	ECsignature, marshalerr := asn1.Marshal(ECDSASignature{r, s})
	if marshalerr != nil {
		return "Error in generating EC signature", errors.New("asn1.Marshal failed to marshal R and S")
	}
	b64sig := B64Encode(ECsignature)
	token := b64cert + "." + b64sig

	return token, nil

}

//VerifyToken verifies token signed by either ECDSA or RSA
func VerifyToken(token string, body []byte) error {
	if token == "" {
		return errors.New("Token cannot be an empty string")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("Invalid token format; expecting 2 parts separated by '.'")
	}
	b64Body := B64Encode(body)
	b64cert := parts[0]
	b64sig, err := B64Decode(parts[1])
	if err != nil {
		return errors.New("Failed to decode base64 encoded signature")
	}
	certDecoded, err := B64Decode(b64cert)
	if err != nil {
		return errors.New("Failed to decode base64 encoded x509 cert")
	}
	sigString := b64Body + "." + b64cert

	block, _ := pem.Decode(certDecoded)
	if block == nil {
		return errors.New("Error in creating cert block")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("Error in parsing x509 cert given Block Bytes")
	}
	publicKey := x509Cert.PublicKey
	hash := sha512.New384()
	hash.Write([]byte(sigString))
	h := hash.Sum(nil)

	switch publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA384, h[:], b64sig)
		return err
	case *ecdsa.PublicKey:
		ecdsaSignature := new(ECDSASignature)
		_, err := asn1.Unmarshal(b64sig, ecdsaSignature)
		if err != nil {
			return errors.New("Failed to unmarshal EC signature to R and S")
		}
		verified := ecdsa.Verify(publicKey.(*ecdsa.PublicKey), h, ecdsaSignature.R, ecdsaSignature.S)
		if verified == true {
			return nil
		}
	}
	return errors.New("Token verification failed")
}

//GetECPrivateKey get *ecdsa.PrivateKey from key pem
func GetECPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the given PEM-encoded ECDSA key")
	}
	ECprivKey, err := x509.ParseECPrivateKey(decoded.Bytes)
	if err != nil {
		return nil, errors.New("Error in parsing EC PKCS1 PrivateKey")
	}
	return ECprivKey, nil
}

//GetRSAPrivateKey get *rsa.PrivateKey from key pem
func GetRSAPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the given PEM-encoded RSA key")
	}
	RSAprivKey, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)
	if err != nil {
		return nil, errors.New("Error in parsing RSA PKCS1 PrivateKey")
	}
	return RSAprivKey, nil
}

// B64Encode base64 encodes bytes
func B64Encode(buf []byte) string {
	return base64.RawStdEncoding.EncodeToString(buf)
}

// B64Decode base64 decodes a string
func B64Decode(str string) (buf []byte, err error) {
	return base64.RawStdEncoding.DecodeString(str)
}

// GetDB returns DB
func GetDB(driver string, dbPath string) (*sqlx.DB, error) {
	return sqlx.Open(driver, dbPath)
}

// StrContained returns true if 'str' is in 'strs'; otherwise return false
func StrContained(str string, strs []string) bool {
	for _, s := range strs {
		if strings.ToLower(s) == strings.ToLower(str) {
			return true
		}
	}
	return false
}

//CreateTables creates user, group, and certificate tables
func CreateTables(DBdriver string, dataSrouce string) (*sqlx.DB, error) {
	db, err := GetDB(DBdriver, dataSrouce)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS Users (id VARCHAR(64), enrollmentId VARCHAR(100), token BLOB, type VARCHAR(64), metadata VARCHAR(256), state INTEGER, key BLOB)"); err != nil {
		return nil, err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS Groups (name VARCHAR(64), parentID VARCHAR(64))"); err != nil {
		return nil, err
	}

	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS certificates (serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"); err != nil {
		return nil, err
	}

	return db, nil
}

// HTTPRequestToString returns a string for an HTTP request for debuggging
func HTTPRequestToString(req *http.Request) string {
	body, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	return fmt.Sprintf("%s %s\nAuthorization: %s\n%s",
		req.Method, req.URL, req.Header.Get("authorization"), string(body))
}

// GetDefaultHomeDir returns the default cop home
func GetDefaultHomeDir() string {
	home := os.Getenv("COP_HOME")
	if home == "" {
		home = os.Getenv("HOME")
		if home != "" {
			home = home + "/.cop"
		}
	}
	if home == "" {
		home = "/var/hyperledger/production/.cop"
	}
	return home
}
