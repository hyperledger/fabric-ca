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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"testing"
)

const (
	testName = "CertificateTest"
)

//Testing for self signed cert
func TestSelfSignedCert(t *testing.T) {

	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate EC Key Pair")
	}

	extraExtensionData := []byte("extra extension")
	var pkixExtension = []pkix.Extension{
		{
			Id:    []int{1, 2, 3, 4},
			Value: extraExtensionData,
		},
	}

	certSpec := parseCertificateRequest(jsonString, big.NewInt(1234567), &privKey.PublicKey, x509.KeyUsageDigitalSignature, pkixExtension)
	//certSpec.pub = &privKey.PublicKey

	rawcert, _ := newCertificateFromSpec(certSpec)
	if rawcert != nil {

		err := ioutil.WriteFile("testcert.der", rawcert, 0777)
		if err != nil {
			t.Fatalf("Problem in writing file")
		}
	}
}
