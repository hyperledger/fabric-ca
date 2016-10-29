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
