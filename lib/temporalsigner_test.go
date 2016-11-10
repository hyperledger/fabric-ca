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

import "testing"

func getTemporalSigner() *TemporalSigner {
	temporal := newTemporalSigner([]byte("key"), []byte("cert"))
	return temporal
}

func TestTemporalSigner(t *testing.T) {
	temporal := getTemporalSigner()
	testRenew(temporal, t)
}

// Place holder test, method has not yet been implemented
func testRenew(temporal *TemporalSigner, t *testing.T) {
	temporal.Renew()
}

func testRevoke(temporal *TemporalSigner, t *testing.T) {
	temporal.Revoke()
}
