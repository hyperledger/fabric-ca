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
	"strconv"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/stretchr/testify/assert"
)

func TestRegistrarAttribute(t *testing.T) {
	os.RemoveAll(rootDir)
	os.RemoveAll("../testdata/msp")
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll("../testdata/msp")

	var err error

	srv := TestGetRootServer(t)
	registry := &srv.CA.Config.Registry

	// admin2 own attributes but does not have 'hf.Registrar.Attributes' attribute
	id := CAConfigIdentity{
		Name:           "admin2",
		Pass:           "admin2pw",
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: -1,
		Attrs: map[string]string{
			attrRoles:   allRoles,
			attrRevoker: "true",
			"a.b":       "val1",
		},
	}
	registry.Identities = append(registry.Identities, id)

	// admin3 has 'hf.Registrar.Attributes' attribute
	id = CAConfigIdentity{
		Name:           "admin3",
		Pass:           "admin3pw",
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: -1,
		Attrs: map[string]string{
			attrRoles:          allRoles,
			attrDelegateRoles:  allRoles,
			attrRevoker:        "true",
			attrIntermediateCA: "true",
			attrRegistrarAttr:  "a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes",
		},
	}
	registry.Identities = append(registry.Identities, id)

	err = srv.Start()
	if !assert.NoError(t, err, "Failed to start server") {
		t.Fatal("Failed to start server: ", err)
	}

	// Enroll admin2
	client := getTestClient(rootPort)
	registrar, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	// Negative case: Registrar does not have the attribute 'hf.Registrar.Attributes'
	_, err = registrar.Identity.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  "fake.attribute",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrMissingRegAttr))
	}

	// Negative case: Registrar does not own 'hf.Registrar.Attributes'
	_, err = registrar.Identity.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  attrRegistrarAttr,
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrMissingRegAttr))
	}

	// Negative case: Registrar owns this attribute but does not have the attribute 'hf.Registrar.Attributes'
	_, err = registrar.Identity.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  attrRevoker,
				Value: "false",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with an attribute that is not part of 'hf.Registrar.Attributes'") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrMissingRegAttr))
	}

	// Enroll request for admin3
	registrar, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin3",
		Secret: "admin3pw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin3' user")

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*
	_, err = registrar.Identity.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "a.b.*",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrRegAttrAuth))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "a.b.c.d",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrRegAttrAuth))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "test",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrRegAttrAuth))
	}

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*
	_, err = registrar.Identity.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "a.b.c",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user3",
		[]api.Attribute{
			api.Attribute{
				Name:  "testattr1",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user4",
		[]api.Attribute{
			api.Attribute{
				Name:  "x.y.*",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Failed to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user5",
		[]api.Attribute{
			api.Attribute{
				Name:  "x.y.z",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user6",
		[]api.Attribute{
			api.Attribute{
				Name:  attrRegistrarAttr,
				Value: "a.b.c, x.y.*",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user7",
		[]api.Attribute{
			api.Attribute{
				Name:  attrRegistrarAttr,
				Value: "a.b, x.y",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrRegAttrAuth))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user7",
		[]api.Attribute{
			api.Attribute{
				Name:  attrRegistrarAttr,
				Value: "a.b.c, x.y",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrRegAttrAuth))
	}

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user7",
		[]api.Attribute{
			api.Attribute{
				Name:  attrRegistrarAttr,
				Value: "a.b.c",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user8",
		[]api.Attribute{
			api.Attribute{
				Name:  attrRegistrarAttr,
				Value: "x.y.z.z",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user9",
		[]api.Attribute{
			api.Attribute{
				Name:  "attr$",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user10",
		[]api.Attribute{
			api.Attribute{
				Name:  "*",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrRegAttrAuth))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes"
	_, err = registrar.Identity.Register(registerTestUser("user10",
		[]api.Attribute{
			api.Attribute{
				Name:  "w.x.y.z",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(ErrRegAttrAuth))
	}

	// Enroll request for admin
	registrar, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	// Positive case: Registrar's hf.Registrar.Attribute = *
	_, err = registrar.Identity.Register(registerTestUser("user10",
		[]api.Attribute{
			api.Attribute{
				Name:  "*",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Failed to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = *
	_, err = registrar.Identity.Register(registerTestUser("user11",
		[]api.Attribute{
			api.Attribute{
				Name:  "made.up.attribute",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	err = srv.Stop()
	assert.NoError(t, err, "Failed to start server")
}

func registerTestUser(username string, attribute []api.Attribute) *api.RegistrationRequest {
	return &api.RegistrationRequest{
		Name:        username,
		Affiliation: "org2",
		Attributes:  attribute,
	}
}

func TestAffiliationAndTypeCheck(t *testing.T) {
	os.RemoveAll(rootDir)
	os.RemoveAll("../testdata/msp")
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll("../testdata/msp")

	var err error

	srv := TestGetRootServer(t)

	registry := &srv.CA.Config.Registry

	// admin2 own attributes but does not have 'hf.Registrar.Attributes' attribute
	id := CAConfigIdentity{
		Name:           "admin2",
		Pass:           "admin2pw",
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: -1,
		Attrs: map[string]string{
			attrRoles: allRoles,
		},
	}
	registry.Identities = append(registry.Identities, id)

	err = srv.Start()
	if !assert.NoError(t, err, "Failed to start server") {
		t.Fatal("Failed to start server: ", err)
	}

	// Enroll admin2
	client := getTestClient(rootPort)
	enrollResp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	registrar := enrollResp.Identity

	// Negative case: Registrar does not have the attribute 'hf.Registrar.Attributes'
	_, err = registrar.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Affiliation: "org2dept1",
	})
	assert.Error(t, err, "Should have failed to register, registrar with affiliation 'org1' can't register 'org1dept1'")

	_, err = registrar.Register(&api.RegistrationRequest{
		Name:        "testuser",
		Affiliation: "org2",
	})
	assert.NoError(t, err, "Failed to register user 'testuser' with appropriate affiliation")

	_, err = registrar.Register(&api.RegistrationRequest{
		Name:        "testuser2",
		Affiliation: "org2.dept1",
	})
	assert.NoError(t, err, "Failed to register user 'testuser2' with appropriate affiliation")

	_, err = registrar.Register(&api.RegistrationRequest{
		Name: "testuser3",
	})
	assert.NoError(t, err, "Failed to register user 'testuser2' with appropriate affiliation")

	db := srv.CA.registry

	user, err := db.GetUser("testuser3", nil)
	assert.NoError(t, err, "Failed to get user")

	assert.Equal(t, "user", user.GetType(), "Failed to set correct default type for a registering user")
	assert.Equal(t, "org2", GetUserAffiliation(user), "Failed to set correct default affiliation for a registering userr")

	err = srv.Stop()
	assert.NoError(t, err, "Failed to start server")
}
