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
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib"
	yaml "gopkg.in/yaml.v2"
)

// IdentityType represents type of identity in the fabric
type IdentityType string

const (
	// User user identity type
	User IdentityType = "User"
	// Peer peer identity type
	Peer = "Peer"
	// Validator validator identity type
	Validator = "Validator"
)

// TestRequest represents request properties from
// which a request payload object can be constructed
type TestRequest map[string]interface{}

// Test represents a fabric-ca test
type Test struct {
	Name   string      `yaml:"name"`
	Repeat int         `yaml:"repeat,omitempty"`
	Req    TestRequest `yaml:"req,omitempty"`
}

type testConfig struct {
	ServerURL      string           `yaml:"serverURL"`
	ConfigHome     string           `yaml:"caConfigHome"`
	NumUsers       int              `yaml:"numClients"`
	NumReqsPerUser int              `yaml:"numReqsPerClient"`
	TestSeq        []Test           `yaml:"testSeq"`
	Affiliation    string           `yaml:"affiliation"`
	CAClientConfig lib.ClientConfig `yaml:"caClientConfig"`
}

// enrollmentID encapsulates an identity's name and type
type enrollmentID struct {
	ID *string
	it *IdentityType
}

var (
	testCfg     testConfig
	testCfgFile *string
)

func main() {
	t0 := time.Now()
	testCfgFile = flag.String("config", "testConfig.yml", "Fully qualified name of the test configuration file")
	flag.Parse()

	// Create CA client config
	err := readConfig()
	if err != nil {
		log.Printf("Failed to create client config: %v", err)
		return
	}

	// Enroll boostrap user
	bootID, err1 := enrollBootstrapUser(&testCfg.ServerURL,
		&testCfg.ConfigHome, &testCfg.CAClientConfig)
	if err1 != nil {
		log.Printf("Failed to enroll bootstrap user: %v", err1)
		return
	}

	fin := make(chan testClientRes, testCfg.NumUsers)

	var wg sync.WaitGroup
	for i := 0; i < testCfg.NumUsers; i++ {
		c := getTestClient(i, &testCfg.ConfigHome, &testCfg.CAClientConfig, bootID)
		if err != nil {
			log.Printf("Failed to get client: %v", err)
			continue
		}
		// Increment the WaitGroup counter
		wg.Add(1)
		go func() {
			// Decrement the counter when the goroutine completes
			defer wg.Done()
			c.runTests(fin)
		}()
	}
	wg.Wait()
	t1 := time.Now()
	log.Printf("Load test finished in %v seconds\n", t1.Sub(t0).Seconds())
	for i := 0; i < testCfg.NumUsers; i++ {
		log.Println(<-fin)
	}
}

// Enrolls bootstrap user and sets the cfg global object
func enrollBootstrapUser(surl *string, configHome *string,
	cfg *lib.ClientConfig) (id *lib.Identity, err error) {
	var resp *lib.EnrollmentResponse
	resp, err = cfg.Enroll(*surl, *configHome)
	if err != nil {
		log.Printf("Enrollment of boostrap user failed: %v", err)
		return id, err
	}
	log.Printf("Successfully enrolled boostrap user")

	id = resp.Identity
	cfg.ID.Name = id.GetName()
	return id, err
}

// Reads test config
func readConfig() error {
	tcFile, e := ioutil.ReadFile(*testCfgFile)
	if e != nil {
		log.Printf("Failed to read configuration file '%s': %v", *testCfgFile, e)
		os.Exit(1)
	}
	yaml.Unmarshal(tcFile, &testCfg)

	uo, err := url.Parse(testCfg.ServerURL)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s://%s", uo.Scheme, uo.Host)
	testCfg.CAClientConfig.URL = u

	// Make config home absolute
	if !filepath.IsAbs(testCfg.ConfigHome) {
		testCfg.ConfigHome, err = filepath.Abs(testCfg.ConfigHome)
		if err != nil {
			log.Printf("Failed to get full path of config file: %s", err)
		}
	}

	log.Printf("Config created: %+v", testCfg)
	return nil
}

// Returns a random affiliation
func getAffiliation() string {
	return testCfg.Affiliation
}

// Returns a random enrollment ID
func genEnrollmentID(it IdentityType) (eid *enrollmentID, err error) {
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	uuid := fmt.Sprintf("%s-%X-%X-%X-%X-%X", it, b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	eid = &enrollmentID{
		ID: &uuid,
		it: &it,
	}
	return
}

// Returns identity type based on the value of i
func getIdentityType(i int) IdentityType {
	tipe := i % 3
	switch tipe {
	case 0:
		return User
	case 1:
		return Peer
	case 2:
		return Validator
	default:
		return User
	}
}

func (tr TestRequest) getTCertsReq() *api.GetTCertBatchRequest {
	count := tr["count"].(int)
	prekey := tr["prekey"].(string)
	disableKdf := tr["disable_kdf"].(bool)
	encryptAttrs := tr["encrypt_attrs"].(bool)
	return &api.GetTCertBatchRequest{
		Count:                count,
		PreKey:               prekey,
		DisableKeyDerivation: disableKdf,
		EncryptAttrs:         encryptAttrs,
	}
}

func (tr TestRequest) getEnrollmentReq() *api.EnrollmentRequest {
	name := tr["name"].(string)
	pass := tr["pass"].(string)
	return &api.EnrollmentRequest{
		Name:   name,
		Secret: pass,
	}
}
