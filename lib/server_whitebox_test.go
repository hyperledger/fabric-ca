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
	"os"
	"testing"
)

const (
	serverPort      = 7060
	affiliationName = "org1"
)

// TestGetAffliation checks if there is one record for the
// affilition 'org1' in the database after starting the server
// two times. This test is to make sure server does not create
// duplicate affiliations in the database every time it is
// started.
func TestGetAffliation(t *testing.T) {
	defer func() {
		err := os.RemoveAll("../testdata/ca-cert.pem")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("../testdata/fabric-ca-server.db")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
		err = os.RemoveAll("../testdata/msp")
		if err != nil {
			t.Errorf("RemoveAll failed: %s", err)
		}
	}()
	// Start the server at an available port (using port 0 will make OS to
	// pick an available port)
	srv := getServer(serverPort, testdataDir, "", -1, t)

	err := srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %v", err)
	}
	err = srv.Stop()
	if err != nil {
		t.Fatalf("Server stop failed: %v", err)
	}

	err = srv.Start()
	if err != nil {
		t.Fatalf("Server start failed: %v", err)
	}
	defer func() {
		err = srv.Stop()
		if err != nil {
			t.Errorf("Failed to stop server: %s", err)
		}
	}()

	afs := []AffiliationRecord{}
	err = srv.db.Select(&afs, srv.db.Rebind(getAffiliationQuery), affiliationName)
	t.Logf("Retrieved %+v for the affiliation %s", afs, affiliationName)
	if err != nil {
		t.Fatalf("Failed to get affiliation %s: %v", affiliationName, err)
	}
	if len(afs) != 1 {
		t.Fatalf("Found 0 or more than one record for the affiliation %s in the database, expected 1 record", affiliationName)
	}
}
