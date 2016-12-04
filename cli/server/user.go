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

package server

import (
	"fmt"

	"github.com/cloudflare/cfssl/log"
)

// userHasAttribute returns true if the user has the attribute
func userHasAttribute(username, attrname string) error {
	val, err := getUserAttrValue(username, attrname)
	if err != nil {
		return err
	}
	if val == "" {
		return fmt.Errorf("user '%s' does not have attribute '%s'", username, attrname)
	}
	return nil
}

// getUserAttrValue returns a user's value for an attribute
func getUserAttrValue(username, attrname string) (string, error) {
	log.Debugf("getUserAttrValue user=%s, attr=%s", username, attrname)
	user, err := userRegistry.GetUser(username, attrname)
	if err != nil {
		return "", err
	}
	attrval := user.GetAttribute(attrname)
	log.Debugf("getUserAttrValue user=%s, name=%s, value=%s", username, attrname, attrval)
	return attrval, nil

}
