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
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/stretchr/stew/objects"
)

func TestRSASignAndVerify(t *testing.T) {
	privKeyBuff, err := ioutil.ReadFile("../testdata/privatekey.pem")
	if err != nil {
		t.Fatalf("Unable to read private key PEM from file: %s", err)
	}
	rsaPrivateKey, err := GetPrivateKey(string(privKeyBuff))
	if err != nil {
		t.Fatalf("Unable to get private key: %s", err)
	}
	pubKeyBuff, err := ioutil.ReadFile("../testdata/publickey.pem")
	if err != nil {
		t.Fatalf("Error reading public key PEM file: %v", err)
	}
	rsapublicKey, err := GetPublicKey(string(pubKeyBuff))
	if err != nil {
		t.Fatalf("Unable to get RSA public key: %s", err)
	}
	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")
	message := []byte(jsonString)
	signature := RSASign(message, "SHA384", rsaPrivateKey)

	rsaverified := RSAVerifySig(rsapublicKey, "SHA384", signature, []byte(ConvertJSONFileToJSONString("../testdata/tcertrequest.json")))
	if rsaverified == false {
		t.Fatalf("Verification failed in TestRSASignAndVerify")
	}
}

func TestECSignAndVerify(t *testing.T) {
	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../testdata/signature.json")
	signedJSON := SignECMessage(jsonString, signatureJSON)
	ECverified := VerifyECMessage(jsonString, signedJSON)
	if ECverified == false {
		t.Fatalf("Verification failed ")
	}
}

func TestRSAPubKeyAltered(t *testing.T) {
	privKeyBuff, err := ioutil.ReadFile("../testdata/privatekey.pem")
	if err != nil {
		t.Fatalf("Unable to read RSA private key PEM from file")
	}
	rsaPrivateKey, err := GetPrivateKey(string(privKeyBuff))
	if err != nil {
		log.Fatalf("Cannot get PrivateKey")
	}
	pubKeyBuff, err := ioutil.ReadFile("../testdata/publickey.pem")
	if err != nil {
		t.Fatalf("Unable to read RSA public key PEM from file")
	}
	rsapublicKey, err := GetPublicKey(string(pubKeyBuff))
	if err != nil {
		t.Fatalf("Unable to get RSA public key")
	}
	//Added 1 to publicKey modulus N will cause verification to fail
	rsapublicKey.N = new(big.Int).Add(rsapublicKey.N, big.NewInt(1))

	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")
	message := []byte(jsonString)
	signature := RSASign(message, "SHA384", rsaPrivateKey)

	isrsaverified := RSAVerifySig(rsapublicKey, "SHA384", signature, []byte(ConvertJSONFileToJSONString("../testdata/tcertrequest.json")))
	if isrsaverified {
		t.Fatalf("Verification failed due to RSA public key altered.")
	}

}

func TestECMessageAltered(t *testing.T) {
	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../testdata/signature.json")
	signedJSON := SignECMessage(jsonString, signatureJSON)

	jsonMap, _ := objects.NewMapFromJSON(signedJSON)
	key := "ECSignature.R"
	_ = jsonMap.Set(key, "newRvalue")
	newsignedJSON, _ := jsonMap.JSON()

	isECverified := VerifyECMessage(jsonString, newsignedJSON)
	if isECverified {
		t.Fatalf("Verification failed due to altered message")
	}
}

// func TestCertExpiry(t *testing.T) {
// 	jsonString := ConvertJSONFileToJSONString("../testdata/TCertRequest.json")
// 	signatureJSON := ConvertJSONFileToJSONString("../testdata/Signature.json")
// 	isVerfied := VerifyMessage(jsonString, SignECMessage(jsonString, signatureJSON))
// 	if isVerfied == false {
// 		t.Fatalf("Verification failed due to certificate expired")
// 	}
// }

func TestVerifyMessage(t *testing.T) {
	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")
	signatureJSON := ConvertJSONFileToJSONString("../testdata/signature.json")
	isVerfied := VerifyMessage(jsonString, SignECMessage(jsonString, signatureJSON))
	if isVerfied == false {
		t.Fatalf("Verification failed due to certificate expired")
	}
}

func TestGenNumber(t *testing.T) {
	var numlen int64
	numlen = 20
	GenNumber(big.NewInt(numlen))
}
