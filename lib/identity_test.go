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
	"io/ioutil"
	"testing"
)

func getIdentity() *Identity {
	key, _ := ioutil.ReadFile("../tesdata/ec-key.pem")
	cert, _ := ioutil.ReadFile("../tesdata/ec.pem")
	id := newIdentity(nil, "test", key, cert)
	return id
}

func TestIdentity(t *testing.T) {
	id := getIdentity()
	testIdentityMarshalling(id, t)
	testGetName(id, t)
	testGetPublicSigner(id, t)
	testGetAttributeNames(id, t)
	testDelete(id, t)
}

func testIdentityMarshalling(id *Identity, t *testing.T) {
	// identity := `{"registrar":{"name":"admin","publicSigner":{"cert":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIvVENDQWFTZ0F3SUJBZ0lVVmE1WkpVd0ZTcU9MVjFRcU94clY3TkVadnJRd0NnWUlLb1pJemowRUF3SXcKYlRFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ1RDa05oYkdsbWIzSnVhV0V4RmpBVUJnTlZCQWNURFZOaApiaUJHY21GdVkybHpZMjh4RXpBUkJnTlZCQW9UQ2tOc2IzVmtSbXhoY21VeEhEQWFCZ05WQkFzVEUxTjVjM1JsCmJYTWdSVzVuYVc1bFpYSnBibWN3SGhjTk1UWXhNVEF6TURVeE9EQXdXaGNOTVRjeE1UQXpNRFV4T0RBd1dqQVEKTVE0d0RBWURWUVFERXdWaFpHMXBiakJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCT0xtT081dwo3REh6RUtNdkpJZmxwZjhQb1Z5dk1Uays1UmorQ1NBcVhQQ0NoNndPTi9yMnAxZjF6cDRmQXhVak96S1VMNCtrCnRpVm9pVHJmUUJzY010bWpmekI5TUE0R0ExVWREd0VCL3dRRUF3SUZvREFkQmdOVkhTVUVGakFVQmdnckJnRUYKQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVEFRSC9CQUl3QURBZEJnTlZIUTRFRmdRVUJqc2RIV3RPcEZQTQpSZ3VJT3VITm1iaDdKem93SHdZRFZSMGpCQmd3Rm9BVWZrMTRuOXM0M25NakNpNWdWWnZuRG4vUWhWY3dDZ1lJCktvWkl6ajBFQXdJRFJ3QXdSQUlnWjJLYVU5R29CYzhqQ0pRTDdTcDg2RUVXT282UXJzK0FpdWV5VVIwMVdtVUMKSUF1RE1wSTdMOXJvREpjV3Y5WWF3NmwzdEVBYTBmdVJGY21ncFFXWEQ4eUkKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=","key":"LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUFMVkFWK044azdOOXhvSEtOV3pzUFc5N0g2TFAvRlNkb2lKeWtaY2xRTkFvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFNHVZNDduRHNNZk1Rb3k4a2grV2wvdytoWEs4eE9UN2xHUDRKSUNwYzhJS0hyQTQzK3ZhbgpWL1hPbmg4REZTTTdNcFF2ajZTMkpXaUpPdDlBR3h3eTJRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="}}}`

	_, err := id.Serialize()
	if err != nil {
		t.Error("Failed to serialize to identity object")
	}
}

func testGetName(id *Identity, t *testing.T) {
	name := id.GetName()
	if name != "test" {
		t.Error("Incorrect name retrieved")
	}
}

func testGetPublicSigner(id *Identity, t *testing.T) {
	publicSigner := id.GetPublicSigner()
	if publicSigner == nil {
		t.Error("No public signer returned")
	}
}

// Place holder test, method has not yet been implemented
func testGetAttributeNames(id *Identity, t *testing.T) {
	id.GetAttributeNames()
}

// Place holder test, method has not yet been implemented
func testDelete(id *Identity, t *testing.T) {
	id.Delete()
}
