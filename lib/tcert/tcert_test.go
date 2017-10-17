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

package tcert

import (
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
)

func TestTCertWithoutAttribute(t *testing.T) {

	log.Level = log.LevelDebug

	// Get a manager
	mgr := getMgr(t)
	if mgr == nil {
		return
	}

	ecert, err := LoadCert("/")
	if err == nil {
		t.Error("Should have failed")
	}

	ecert, err = LoadCert("../../testdata/ec.pem")
	if err != nil {
		t.Errorf("LoadCert unable to load ec.pem %v", err)
	}

	batchReq := &GetTCertBatchRequest{}
	batchReq.Count = 1
	batchReq.PreKey = "anyroot"

	resp, err := mgr.GetBatch(batchReq, ecert)
	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)
		return
	}
	if len(resp.TCerts) != 1 {
		t.Errorf("Returned incorrect number of TCerts: expecting 1 but found %d", len(resp.TCerts))
	}

}

func TestTCertWitAttributes(t *testing.T) {

	log.Level = log.LevelDebug

	// Get a manager
	mgr := getMgr(t)
	if mgr == nil {
		return
	}

	ecert, err := LoadCert("../../testdata/ec.pem")
	if err != nil {
		return
	}
	var Attrs = []api.Attribute{
		{
			Name:  "SSN",
			Value: "123-456-789",
		},

		{
			Name:  "Income",
			Value: "USD",
		},
	}
	batchReq := &GetTCertBatchRequest{}
	batchReq.Count = 2
	batchReq.EncryptAttrs = true
	batchReq.Attrs = Attrs
	batchReq.PreKey = "anotherprekey"
	resp, err := mgr.GetBatch(batchReq, ecert)
	if err != nil {
		t.Errorf("Error from GetBatch: %s", err)
		return
	}
	if len(resp.TCerts) != 2 {
		t.Errorf("Returned incorrect number of certs: expecting 2 but found %d", len(resp.TCerts))
	}

}

func getMgr(t *testing.T) *Mgr {
	keyFile := "../../testdata/ec-key.pem"
	certFile := "../../testdata/ec.pem"
	mgr, err := LoadMgr(keyFile, certFile, util.GetDefaultBCCSP())
	if err != nil {
		t.Errorf("failed loading mgr: %s", err)
		return nil
	}
	return mgr
}
