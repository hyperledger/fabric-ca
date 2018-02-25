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

	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp/factory"
)

func getIdentity() *Identity {
	key, _ := util.ImportBCCSPKeyFromPEM("../tesdata/ec-key.pem", factory.GetDefault(), true)
	cert, _ := ioutil.ReadFile("../tesdata/ec.pem")
	id := newIdentity(nil, "test", key, cert)
	return id
}

func TestIdentity(t *testing.T) {
	id := getIdentity()
	testGetName(id, t)
	testGetECert(id, t)
}

func testGetName(id *Identity, t *testing.T) {
	name := id.GetName()
	if name != "test" {
		t.Error("Incorrect name retrieved")
	}
}

func testGetECert(id *Identity, t *testing.T) {
	ecert := id.GetECert()
	if ecert == nil {
		t.Error("No ECert was returned")
	}
}
