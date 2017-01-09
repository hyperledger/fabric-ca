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
	"path"
	"path/filepath"
	"strings"
	"time"

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
func ReadFile(file string) ([]byte, error) {
	return ioutil.ReadFile(file)
}

// WriteFile writes a file
func WriteFile(file string, buf []byte, perm os.FileMode) error {
	return ioutil.WriteFile(file, buf, perm)
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
func Marshal(from interface{}, what string) ([]byte, error) {
	buf, err := json.Marshal(from)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal %s: %s", what, err)
	}
	return buf, nil
}

// Unmarshal from bytes
func Unmarshal(from []byte, to interface{}, what string) error {
	err := json.Unmarshal(from, to)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal %s: %s", what, err)
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
		return "", errors.New("Failed to PEM decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("Error from x509.ParseCertificate: %s", err)
	}
	publicKey := x509Cert.PublicKey

	var token string

	switch publicKey.(type) {
	case *rsa.PublicKey:
		token, err = GenRSAToken(cert, key, body)
		if err != nil {
			return "", err
		}
	case *ecdsa.PublicKey:
		token, err = GenECDSAToken(cert, key, body)
		if err != nil {
			return "", err
		}
	}
	return token, nil
}

//GenRSAToken signs the http body and cert with RSA using RSA private key
func GenRSAToken(cert []byte, key []byte, body []byte) (string, error) {
	privKey, err := GetRSAPrivateKey(key)
	if err != nil {
		return "", err
	}
	b64body := B64Encode(body)
	b64cert := B64Encode(cert)
	bodyAndcert := b64body + "." + b64cert
	hash := sha512.New384()
	hash.Write([]byte(bodyAndcert))
	h := hash.Sum(nil)
	RSAsignature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA384, h[:])
	if err != nil {
		return "", fmt.Errorf("Error from rsa.SignPKCS1v15: %s", err)
	}
	b64sig := B64Encode(RSAsignature)
	token := b64cert + "." + b64sig

	return token, nil
}

//GenECDSAToken signs the http body and cert with ECDSA using EC private key
func GenECDSAToken(cert []byte, key []byte, body []byte) (string, error) {
	privKey, err := GetECPrivateKey(key)
	if err != nil {
		return "", err
	}
	b64body := B64Encode(body)
	b64cert := B64Encode(cert)
	bodyAndcert := b64body + "." + b64cert
	hash := sha512.New384()
	hash.Write([]byte(bodyAndcert))
	h := hash.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, h)
	if err != nil {
		return "", fmt.Errorf("Failed in ecdsa.Sign: %s", err)
	}
	ECsignature, err := asn1.Marshal(ECDSASignature{r, s})
	if err != nil {
		return "", fmt.Errorf("Failed in asn1.Marshal: %s", err)
	}
	b64sig := B64Encode(ECsignature)
	token := b64cert + "." + b64sig

	return token, nil

}

// VerifyToken verifies token signed by either ECDSA or RSA and
// returns the associated user ID
func VerifyToken(token string, body []byte) (*x509.Certificate, error) {
	x509Cert, b64Cert, b64Sig, err := DecodeToken(token)
	if err != nil {
		return nil, err
	}
	sig, err := B64Decode(b64Sig)
	if err != nil {
		return nil, fmt.Errorf("Invalid base64 encoded signature in token: %s", err)
	}
	b64Body := B64Encode(body)
	sigString := b64Body + "." + b64Cert
	publicKey := x509Cert.PublicKey
	hash := sha512.New384()
	hash.Write([]byte(sigString))
	h := hash.Sum(nil)
	switch publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA384, h[:], sig)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		ecdsaSignature := new(ECDSASignature)
		_, err := asn1.Unmarshal(sig, ecdsaSignature)
		if err != nil {
			return nil, fmt.Errorf("Failed to unmarshal EC signature to R and S: %s", err)
		}
		verified := ecdsa.Verify(publicKey.(*ecdsa.PublicKey), h, ecdsaSignature.R, ecdsaSignature.S)
		if !verified {
			return nil, errors.New("token verification failed (ecdsa.Verify failed)")
		}
	}
	return x509Cert, nil
}

// DecodeToken extracts an X509 certificate and base64 encoded signature from a token
func DecodeToken(token string) (*x509.Certificate, string, string, error) {
	if token == "" {
		return nil, "", "", errors.New("Invalid token; it is empty")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, "", "", errors.New("Invalid token format; expecting 2 parts separated by '.'")
	}
	b64cert := parts[0]
	certDecoded, err := B64Decode(b64cert)
	if err != nil {
		return nil, "", "", fmt.Errorf("Failed to decode base64 encoded x509 cert: %s", err)
	}
	block, _ := pem.Decode(certDecoded)
	if block == nil {
		return nil, "", "", errors.New("Failed to PEM decode the certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", "", fmt.Errorf("Error in parsing x509 cert given Block Bytes: %s", err)
	}
	return x509Cert, b64cert, parts[1], nil
}

//GetECPrivateKey get *ecdsa.PrivateKey from key pem
func GetECPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the given PEM-encoded ECDSA key")
	}
	ECprivKey, err := x509.ParseECPrivateKey(decoded.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseECPrivateKey failed: %s", err)
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
		return nil, fmt.Errorf("Failure in x509.ParsePKCS1PrivateKey: %s", err)
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

// GetDB returns a handle to an established driver-specific database connection
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

// HTTPRequestToString returns a string for an HTTP request for debuggging
func HTTPRequestToString(req *http.Request) string {
	body, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	return fmt.Sprintf("%s %s\nAuthorization: %s\n%s",
		req.Method, req.URL, req.Header.Get("authorization"), string(body))
}

// HTTPResponseToString returns a string for an HTTP response for debuggging
func HTTPResponseToString(resp *http.Response) string {
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))
	return fmt.Sprintf("statusCode=%d (%s)\n%s",
		resp.StatusCode, resp.Status, string(body))
}

// GetDefaultHomeDir returns the default cop home
func GetDefaultHomeDir() string {
	home := os.Getenv("COP_HOME")
	if home == "" {
		home = os.Getenv("HOME")
		if home != "" {
			home = path.Join(home, "/cop")
		} else {
			home = "/var/hyperledger/fabric/dev/fabric-cop"
		}
	}
	return home
}

// GetX509CertificateFromPEM converts a PEM buffer to an X509 Certificate
func GetX509CertificateFromPEM(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("Failed to PEM decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error from x509.ParseCertificate: %s", err)
	}
	return x509Cert, nil
}

// GetEnrollmentIDFromPEM returns the EnrollmentID from a PEM buffer
func GetEnrollmentIDFromPEM(cert []byte) (string, error) {
	x509Cert, err := GetX509CertificateFromPEM(cert)
	if err != nil {
		return "", err
	}
	return GetEnrollmentIDFromX509Certificate(x509Cert), nil
}

// GetEnrollmentIDFromX509Certificate returns the EnrollmentID from the X509 certificate
func GetEnrollmentIDFromX509Certificate(cert *x509.Certificate) string {
	return cert.Subject.CommonName
}

// MakeFileAbs makes 'file' absolute relative to 'dir' if not already absolute
func MakeFileAbs(file, dir string) (string, error) {
	if file == "" {
		return "", nil
	}
	if filepath.IsAbs(file) {
		return file, nil
	}
	path, err := filepath.Abs(filepath.Join(dir, file))
	if err != nil {
		return "", fmt.Errorf("Failed making '%s' absolute based on '%s'", file, dir)
	}
	return path, nil
}
