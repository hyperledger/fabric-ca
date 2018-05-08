/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
package streamer_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/hyperledger/fabric-ca/lib/streamer"
	"github.com/stretchr/testify/assert"
)

type element struct {
	Name string
	Type string
}

func TestJSONStreamer(t *testing.T) {
	identityCount := 0
	cb := func(decoder *json.Decoder) error {
		ele := &element{}
		err := decoder.Decode(ele)
		if err != nil {
			return err
		}
		identityCount++
		return nil
	}

	const jsonStream = `{"a": "aval", "b": {"foo": [{"foo1":"bar1"}]}, "result": {"identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]}, "errors": [], "c": "cval", "d": "dval", "e": 1.234}`
	dec := json.NewDecoder(strings.NewReader(jsonStream))
	_, err := StreamJSONArray(dec, "result.identities", cb)
	if assert.NoError(t, err, "Failed to correctly stream JSON") {
		assert.True(t, identityCount == 2, "Identity function not called correct number of times")
	}

	const jsonStreamErr = `{"a": "aval", "b": {"foo": [{"foo1":"bar1"}]}, "result": "", "errors": [{"code":20,"message":"Authorization failure"}], "c": "cval", "d": "dval", "e": 1.234}`
	dec = json.NewDecoder(strings.NewReader(jsonStreamErr))
	_, err = StreamJSONArray(dec, "result.identities", cb)
	if assert.Error(t, err, "Should have returned the error in the JSON stream") {
		assert.Contains(t, err.Error(), "Authorization failure")
	}

	const jsonStreamBaderr = `{"a": "aval", "b": {"foo": [{"foo1":"bar1"}]}, "result": {"identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]}, "errors": {"code":20,"message":"Authorization failure"}, "c": "cval", "d": "dval", "e": 1.234}`
	dec = json.NewDecoder(strings.NewReader(jsonStreamBaderr))
	_, err = StreamJSONArray(dec, "result.identities", cb)
	assert.Error(t, err, "Should have failed, errors is not array type")

	const jsonStream3 = `["identities": [{"name": "id1", "type": "type1"}, {"name": "id2"}]`
	dec = json.NewDecoder(strings.NewReader(jsonStream3))
	_, err = StreamJSONArray(dec, "identities", cb)
	assert.Error(t, err, "Should have failed, incorrect opening bracket")

	const jsonStream4 = `{"identities": [[]}`
	dec = json.NewDecoder(strings.NewReader(jsonStream4))
	_, err = StreamJSONArray(dec, "identities", cb)
	assert.Error(t, err, "Should have failed, incorrect number of square brackets")

	const jsonStream5 = `{"a": "aval", "identities": [{]"name": "id1", "type": "type1"}, {"name": "id2"}], "c": "cval}`
	dec = json.NewDecoder(strings.NewReader(jsonStream5))
	_, err = StreamJSONArray(dec, "identities", cb)
	assert.Error(t, err, "Should have failed, incorrect opening square bracket")

	const jsonStream6 = `{"a": "aval", "identities": []{"name": "id1", "type": "type1"}, {"name": "id2"}], "c": "cval"}`
	dec = json.NewDecoder(strings.NewReader(jsonStream6))
	_, err = StreamJSONArray(dec, "identities", cb)
	assert.Error(t, err, "Should have failed, incorrect format of 'identities'")

	const jsonStream7 = `{"a"/ "aval", "identities": {"name": "id1", "type": "type1"}, {"name": "id2"}], "c": "cval"}`
	dec = json.NewDecoder(strings.NewReader(jsonStream7))
	_, err = StreamJSONArray(dec, "identities", cb)
	assert.Error(t, err, "Should have failed, incorrect JSON syntax")

	const jsonStream8 = `{"a": "aval", "identities":[{"name": "id1"}], "errors":[/]}`
	dec = json.NewDecoder(strings.NewReader(jsonStream8))
	_, err = StreamJSONArray(dec, "identities", cb)
	assert.Error(t, err, "Should have failed, invalid JSON format")
}
