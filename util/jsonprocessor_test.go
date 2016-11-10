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
	"os"
	"testing"
)

func TestWriteJSONAsMapToFile(t *testing.T) {
	err := WriteJSONAsMapToFile("driver", "postgres", "../testdata/testingutil.json")
	if err != nil {
		t.Error("Failed to write JSON as a map to file, error: ", err)
	}
	err = WriteJSONAsMapToFile("driver", "sqlite3", "../testdata/testingutil.json")
	if err != nil {
		t.Error("Failed to write JSON as a map to file, error: ", err)
	}
}

func TestConvertJSONFileToJSONString(t *testing.T) {
	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")
	if jsonString == "" {
		t.Error("Failed to convert JSON file to JSON string")
	}
}

func TestGetAttributes(t *testing.T) {
	jsonString := ConvertJSONFileToJSONString("../testdata/tcertrequest.json")
	result := GetAttributes(jsonString)
	if len(result) == 0 {
		t.Error("Failed to get attributes")
	}
}

func TestWriteToJSON(t *testing.T) {
	WriteToJSON("../testdata/test.json", "testing writing to json")

	if _, err := os.Stat("../testdata/test.json"); err != nil {
		if os.IsNotExist(err) {
			t.Error("Failed to write to json file")
		}
	}

	os.Remove("../testdata/test.json")
}
