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
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512" //for SHA384
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/cloudflare/cfssl/log"
)

//GenNumber generates random numbers of type *big.Int with fixed length
func GenNumber(numlen *big.Int) *big.Int {
	lowerBound := new(big.Int).Exp(big.NewInt(10), new(big.Int).Sub(numlen, big.NewInt(1)), nil)
	upperBound := new(big.Int).Exp(big.NewInt(10), numlen, nil)
	randomNum, _ := rand.Int(rand.Reader, upperBound)
	val := new(big.Int).Add(randomNum, lowerBound)
	valMod := new(big.Int).Mod(val, upperBound)

	if valMod.Cmp(lowerBound) == -1 {
		newval := new(big.Int).Add(valMod, lowerBound)
		return newval
	}
	return valMod
}

// GetPrivateKey converts a private key []byte to *rsa.PrivateKey object
// The Private Key has to be PEM encoded
func GetPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("private key PEM block is empty")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Unable to parse private key")
	}
	return priv, nil
}

//GetPublicKey converts publicKey.pem to *rsa.PublicKey
func GetPublicKey(publicKey string) (*rsa.PublicKey, error) {
	var err error
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("public block key is empty")
	}
	var pubKey interface{}
	pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Unable to parse RSA public key")
	}
	return pubKey.(*rsa.PublicKey), nil
}

//VerifyMessage Gets Public Key from Certificate
//Certificate can be in PEM or DER Format
//It verifies both RSA and EC signatures**/
func VerifyMessage(jsonString string, signatureString string) bool {
	var isvalidCert = false
	//Get Cert from the JSON
	ecert := ReadJSONAsMapString(signatureString, "Certificate")

	certificate, _ := base64.StdEncoding.DecodeString(ecert)

	var certificates []*x509.Certificate
	var err error
	block, _ := pem.Decode(certificate)
	if block == nil {
		certificates, err = x509.ParseCertificates(certificate)
		if err != nil {
			log.Fatal("Certificate Parse failed")
		} else {
			isvalidCert = ValidateCert(certificates[0])
			if !isvalidCert {
				log.Fatal("Certificate expired")
				return false
			}
		}
	} else {
		certificates, err = x509.ParseCertificates(block.Bytes)
		if err != nil {
			log.Fatal("Certificatre Parse failed")
		} else {
			isvalidCert = ValidateCert(certificates[0])
			if !isvalidCert {
				log.Fatal("Certificate expired")
				return false
			}
		}
	}
	pub := certificates[0].PublicKey

	if pub == nil {
		log.Fatal("Public Key is nil")
		return false
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		log.Debug("pub is of type RSA:", pub)
		return (VerifyRSAMessageImpl(jsonString, signatureString, pub))
	case *dsa.PublicKey:
		log.Debug("pub is of type DSA:", pub)
	case *ecdsa.PublicKey:
		log.Debug("pub is of type ECDSA:", pub)
		return (VerifyECMessageImpl(jsonString, signatureString, pub))
	default:
		log.Fatal("unknown type of public key")
	}
	return false
}

// RSASign Signs Message as per RSA Algo
// returns RSA bigint String Signature
// ShaAlgo is hard coded right now to SHA384. Will implement dynamic algo**/
func RSASign(message []byte, shaAlgo string, rsaPrivateKey *rsa.PrivateKey) string {
	rng := rand.Reader
	//hashed := sha256.Sum256(message)
	hash := sha512.New384()
	hash.Write(message)
	hashed := hash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA384 /*hash*/, hashed[:])
	if err != nil {
		log.Fatal("Error from signing: ", err)
		return ""
	}
	sig := base64.StdEncoding.EncodeToString(signature)
	return sig

}

// RSAVerifySig Verifies RSA Signature
// return boolean
func RSAVerifySig(publicKey *rsa.PublicKey, hashAlgo string, signature string, message []byte) bool {
	sig, _ := base64.StdEncoding.DecodeString(signature)
	hash := sha512.New384()
	hash.Write(message)
	hashed := hash.Sum(nil)

	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA384, hashed[:], sig)
	if err != nil {
		return false
	}
	return true
}

// VerifyECMessage Verifies EC Message
func VerifyECMessage(JSONString string, signatureString string) bool {
	ecert := ReadJSONAsMapString(signatureString, "Certificate")
	raw, _ := base64.StdEncoding.DecodeString(ecert)
	//Get Cert from the JSON
	//Validate
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		log.Fatal("Error parsing x509 certificate: ", err)
		return false
	}

	pub := cert.PublicKey.(*ecdsa.PublicKey)
	R := ReadJSONAsMapString(signatureString, "ECSignature.R")
	S := ReadJSONAsMapString(signatureString, "ECSignature.S")

	r, s := big.NewInt(0), big.NewInt(0)
	r.SetString(R, 10)
	s.SetString(S, 10)

	hash := sha512.New384()
	hash.Write([]byte(JSONString))
	if ecdsa.Verify(pub, hash.Sum(nil), r, s) == false {
		return false
	}
	return true
}

//VerifyRSAMessageImpl implements the RSA signature verification
func VerifyRSAMessageImpl(jsonString string, signatureString string, publicKey *rsa.PublicKey) bool {
	signature := ReadJSONAsMapString(signatureString, "RSASignature")
	return RSAVerifySig(publicKey, "SHA384", signature, []byte(jsonString))
}

//VerifyECMessageImpl implements the Elliptic Curve signature verification
func VerifyECMessageImpl(JSONString string, signatureString string, pub *ecdsa.PublicKey) bool {
	R := ReadJSONAsMapString(signatureString, "ECSignature.R")
	S := ReadJSONAsMapString(signatureString, "ECSignature.S")

	r, s := big.NewInt(0), big.NewInt(0)
	r.SetString(R, 10)
	s.SetString(S, 10)

	hash := sha512.New384()
	hash.Write([]byte(JSONString))
	if ecdsa.Verify(pub, hash.Sum(nil), r, s) == false {
		return false
	}
	return true
}

//NewSelfSignedCert returns new key ans cert
// Takes JSON string as input
// Returns JSON Strinng with Cert and json Signaure Signature String */
func NewSelfSignedCert() ([]byte, interface{}, error) {
	now := time.Now()
	oneHRLater := now.Add(60 * time.Minute)

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Σ Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: now,
		NotAfter:  oneHRLater, SignatureAlgorithm: x509.ECDSAWithSHA384, SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage, BasicConstraintsValid: true,
		IsCA: true, OCSPServer: []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"}, DNSNames: []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")}, PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"}, CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"}, ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
		},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, privKey, nil
}

//ECDSASignDirect signs the message msg and returns R,S using ECDSA
func ECDSASignDirect(signKey interface{}, msg []byte) (*big.Int, *big.Int, error) {
	temp := signKey.(*ecdsa.PrivateKey)
	hash := sha512.New384()
	hash.Write(msg)
	h := hash.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, temp, h)
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}

//SignECMessage generates a certificate and privKey and returns a signedJSON string containing the R and S value.
func SignECMessage(JSONString string, signatureJSON string) string {
	cert, privKey, err := NewSelfSignedCert()
	if err != nil {
		log.Fatal("Error in SignECMessage NewSelfSignedCert fails to create cert/privKey:", err)
	}
	raw := []byte(JSONString)
	r, s, err := ECDSASignDirect(privKey, raw)
	if err != nil {
		log.Fatal("Error in SignECMessage ECDSASignDirect fails to sign:", err)
	}
	var R = r.String()
	var S = s.String()

	encodedCert := base64.StdEncoding.EncodeToString(cert)

	valueMap := make(map[string]string)
	valueMap["ECSignature.R"] = R
	valueMap["ECSignature.S"] = S
	valueMap["Certificate"] = encodedCert
	var signedJSON = WriteJSONToString(signatureJSON, valueMap)

	return signedJSON
}

//RSASignJSON  Signs JSon string
//jsonString : JSonString to be signed
//signatureJson : json string containing signature and ECert
//certificate : in based64 encoding
//returns JSON String with updated signature */
func RSASignJSON(jsonString string, signatureJSON string, rsaPrivateKey *rsa.PrivateKey, cert string) string {
	message := []byte(jsonString)
	signature := RSASign(message, "SHA384", rsaPrivateKey)
	valueMap := make(map[string]string)
	valueMap["RSASignature"] = signature
	valueMap["Certificate"] = cert
	var signedJSON = WriteJSONToString(signatureJSON, valueMap)

	return signedJSON
}

//ValidateCert checks for expiry in the certificate cert
//Does not check for revocation
func ValidateCert(cert *x509.Certificate) bool {
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	currentTime := time.Now()
	diffFromExpiry := notAfter.Sub(currentTime)
	diffFromStart := currentTime.Sub(notBefore)
	return ((diffFromExpiry > 0) && (diffFromStart > 0))
}
