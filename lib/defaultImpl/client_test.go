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

package defaultImpl

/* Ash/Pho TODO: commenting out this test until working (Keith)
   Some quick comments:
   1) You can't hardcode URL to localhost in client.go
   2) See the "post" function in client.go
   3) For tests that assume a server is running, the test should go in cop_test.go
   
import (
	"github.com/hyperledger/fabric-cop/util"
	"testing"
)

func TestGetTCertBatch(t *testing.T) {
	c := NewClient()
	jsonString := util.ConvertJSONFileToJSONString("../../testdata/TCertRequest.json")
	signatureJSON := util.ConvertJSONFileToJSONString("../../testdata/Signature.json")
	//c.GetTCertBatch makes call to COP server to obtain a batch of transaction certificate
	_, err := c.GetTcertBatch(jsonString, signatureJSON)
	if err != nil {
		t.Fatalf("Failed to get tcerts: ", err)
	}
}
*/
