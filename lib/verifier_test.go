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

package lib

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/hyperledger/fabric-cop/idp"
)

func TestMarshalling(t *testing.T) {
	cert := `{"cert":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIvVENDQWFTZ0F3SUJBZ0lVVmE1WkpVd0ZTcU9MVjFRcU94clY3TkVadnJRd0NnWUlLb1pJemowRUF3SXcKYlRFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ1RDa05oYkdsbWIzSnVhV0V4RmpBVUJnTlZCQWNURFZOaApiaUJHY21GdVkybHpZMjh4RXpBUkJnTlZCQW9UQ2tOc2IzVmtSbXhoY21VeEhEQWFCZ05WQkFzVEUxTjVjM1JsCmJYTWdSVzVuYVc1bFpYSnBibWN3SGhjTk1UWXhNVEF6TURVeE9EQXdXaGNOTVRjeE1UQXpNRFV4T0RBd1dqQVEKTVE0d0RBWURWUVFERXdWaFpHMXBiakJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCT0xtT081dwo3REh6RUtNdkpJZmxwZjhQb1Z5dk1Uays1UmorQ1NBcVhQQ0NoNndPTi9yMnAxZjF6cDRmQXhVak96S1VMNCtrCnRpVm9pVHJmUUJzY010bWpmekI5TUE0R0ExVWREd0VCL3dRRUF3SUZvREFkQmdOVkhTVUVGakFVQmdnckJnRUYKQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVEFRSC9CQUl3QURBZEJnTlZIUTRFRmdRVUJqc2RIV3RPcEZQTQpSZ3VJT3VITm1iaDdKem93SHdZRFZSMGpCQmd3Rm9BVWZrMTRuOXM0M25NakNpNWdWWnZuRG4vUWhWY3dDZ1lJCktvWkl6ajBFQXdJRFJ3QXdSQUlnWjJLYVU5R29CYzhqQ0pRTDdTcDg2RUVXT282UXJzK0FpdWV5VVIwMVdtVUMKSUF1RE1wSTdMOXJvREpjV3Y5WWF3NmwzdEVBYTBmdVJGY21ncFFXWEQ4eUkKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="}`

	var v Verifier
	err := json.Unmarshal([]byte(cert), &v)
	if err != nil {
		t.Error("err: ", err)
	}

}

func getVerifier() Verifier {
	cert, _ := ioutil.ReadFile("../tesdata/ec.pem")
	v := newVerifier(cert)
	return v
}

func TestVerifier(t *testing.T) {
	v := getVerifier()
	testGetCert(v, t)
	testSerialize(v, t)
	testVerifySelf(v, t)
	testVerify(v, t)
	testVerifyOpts(v, t)
	testVerifyAttributes(v, t)

}

func testGetCert(v Verifier, t *testing.T) {
	cert := v.GetMyCert()
	if cert != nil {
		t.Error("Failed to get cert")
	}
}

func testSerialize(v Verifier, t *testing.T) {
	_, err := v.Serialize()
	if err != nil {
		t.Error("Failed to serialize to verifier object")
	}
}

// Place holder test, method has not yet been implemented
func testVerifySelf(v Verifier, t *testing.T) {
	v.VerifySelf()
}

// Place holder test, method has not yet been implemented
func testVerify(v Verifier, t *testing.T) {
	msg := []byte("")
	sig := []byte("")
	v.Verify(msg, sig)
}

// Place holder test, method has not yet been implemented
func testVerifyOpts(v Verifier, t *testing.T) {
	msg := []byte("")
	sig := []byte("")
	opts := new(idp.SignatureOpts)
	v.VerifyOpts(msg, sig, *opts)
}

// Place holder test, method has not yet been implemented
func testVerifyAttributes(v Verifier, t *testing.T) {
	proof := [][]byte{[]byte("")}
	spec := new(idp.AttributeProofSpec)
	v.VerifyAttributes(proof, spec)
}
