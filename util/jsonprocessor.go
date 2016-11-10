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
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/stretchr/stew/objects"
)

//ReadJSONAsMapFile reads the keyvalue from file system
func ReadJSONAsMapFile(configFileLocation string, stringLocator string) string {
	buff, err := ioutil.ReadFile(configFileLocation)
	if err != nil {
		log.Fatal("error:", err)
	}
	var jsonString = string(buff)
	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	var keyValue = jsonMap.Get(stringLocator).(string)
	return keyValue
}

//ReadJSONAsMapString reads keyvalue from strings
func ReadJSONAsMapString(jsonString string, stringLocator string) string {
	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	var keyValue = jsonMap.Get(stringLocator).(string)

	return keyValue
}

//GetAttributes get attributes from jsonString
//@jsonString : jsonString containing Attributes
//@ returns : map containing attribute name as Key and Attribute Value as value
func GetAttributes(jsonString string) map[string]string {
	if (jsonString == "") || (len(jsonString) == 0) {
		return nil
	}
	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	stringLocator := "TCertBatchRequest.AttributeSet"
	var keyValue = jsonMap.Get(stringLocator)
	valueMap := make(map[string]string)
	for i := range keyValue.([]interface{}) {
		arribute := keyValue.([]interface{})[i]

		attributeName := arribute.(map[string]interface{})["AttributeName"].(string)
		attributeValue := arribute.(map[string]interface{})["AttributeValue"].(string)
		valueMap[attributeName] = attributeValue
	}

	return valueMap

}

/**
*  Read Certificate Request from JSON file
 */

func parseCertificateRequest(jsonstring string, serialNumber *big.Int, pub interface{}, usage x509.KeyUsage, opt []pkix.Extension) *CertificateSpec {

	stringLocator := "TCertBatchRequest.CerificateRequestData"
	jsonMap, _ := objects.NewMapFromJSON(jsonstring)

	//Validity Period is in the units of hours
	certSpec := new(CertificateSpec)
	certSpec.commonName = jsonMap.Get(stringLocator + ".CN").(string)

	certSpec.country = jsonMap.Get(stringLocator + ".C").(string)
	certSpec.State = jsonMap.Get(stringLocator + ".ST").(string)
	certSpec.locality = jsonMap.Get(stringLocator + ".L").(string)
	certSpec.Organization = jsonMap.Get(stringLocator + ".O").(string)
	certSpec.OrganizationUnit = jsonMap.Get(stringLocator + ".OU").(string)
	validityPeriod := jsonMap.Get(stringLocator + ".validityPeriod").(float64)
	certSpec.certificateType = jsonMap.Get("TCertBatchRequest.CertificateType").(float64)
	NotBefore := time.Now()
	NotAfter := NotBefore.Add(time.Duration(validityPeriod) * time.Hour)
	certSpec.NotBefore = NotBefore
	certSpec.NotAfter = NotAfter

	certSpec.serialNumber = serialNumber
	certSpec.pub = pub
	certSpec.usage = usage
	certSpec.ext = &opt

	return certSpec
}

//isAttributeEncryptionEnabled Gets encryption bool flag
func isAttributeEncryptionEnabled(jsonstring string) bool {
	jsonMap, _ := objects.NewMapFromJSON(jsonstring)
	areAttributesEnctypted := jsonMap.Get("TCertBatchRequest.attribute-encryption_enabled").(bool)
	return areAttributesEnctypted
}

//ConvertJSONFileToJSONString converts a file of json format to a json string
func ConvertJSONFileToJSONString(jsonFileLocation string) string {
	buff, err := ioutil.ReadFile(jsonFileLocation)
	if err != nil {
		log.Fatal("Error reading json file:", err)
	}
	var jsonString = string(buff)
	return jsonString
}

//WriteJSONAsMapToFile reads JSON String from File and Updates it with value
func WriteJSONAsMapToFile(stringLocator string, value string, filePath string) error {
	buff, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("Error reading file from given path:", err)
		return err
	}
	var jsonString = string(buff)
	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	_ = jsonMap.Set(stringLocator, value)

	//Write TO File
	f, err := os.Create(filePath)
	if err != nil {
		log.Fatal("Error writing to file:", err)
	}

	defer f.Close()

	jsonString, _ = jsonMap.JSON()
	if _, err = f.WriteString(jsonString); err != nil {
		log.Fatal("Error writing json string:", err)
		return err
	}
	return nil
}

//WriteJSONAsMapToString writes a json map to a json string
func WriteJSONAsMapToString(jsonString string, stringLocator string, value string) string {
	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	_ = jsonMap.Set(stringLocator, value)
	jsonString, _ = jsonMap.JSON()
	return jsonString
}

//WriteJSONToString takes a map as input and returns json map
func WriteJSONToString(jsonString string, valueMap map[string]string) string {
	jsonMap, _ := objects.NewMapFromJSON(jsonString)
	for key, value := range valueMap {
		_ = jsonMap.Set(key, value)
	}
	jsonOutString, _ := jsonMap.JSON()
	return jsonOutString
}

//WriteToJSON reads a file name from configfile and writes json file one at a time
func WriteToJSON(filePath string, cotentToAppend string) {

	_, err := os.Stat(filePath)
	if err != nil {
		_, err := os.Create(filePath)
		if err != nil {
			log.Fatal("Error creating file:", err)
		}
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal("Error opening file:", err)
	}

	defer f.Close()

	if _, err = f.WriteString(cotentToAppend + "\n"); err != nil {
		log.Fatal("Error writing json string:", err)
	}

}
