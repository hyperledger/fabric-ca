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

package lib

import (
	"net/url"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/tls"
)

// ClientConfig is the fabric-ca client's config
type ClientConfig struct {
	URL        string                `yaml:"url,omitempty"`
	TLS        tls.ClientTLSConfig   `yaml:"tls,omitempty"`
	Enrollment api.EnrollmentRequest `yaml:"enrollment,omitempty"`
}

// Enroll a client given the server's URL and the client's home directory.
// The URL may be of the form: http://user:pass@host:port where user and pass
// are the enrollment ID and secret, respectively.
func (c *ClientConfig) Enroll(rawurl, home string) (id *Identity, err error) {
	purl, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if purl.User != nil {
		name := purl.User.Username()
		secret, _ := purl.User.Password()
		c.Enrollment.Name = name
		c.Enrollment.Secret = secret
		purl.User = nil
	}
	c.URL = purl.String()
	c.TLS.Enabled = purl.Scheme == "https"
	client := &Client{HomeDir: home, Config: c}
	return client.Enroll(&c.Enrollment)
}
