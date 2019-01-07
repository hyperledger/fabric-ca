/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package lib

import (
	"os"
	"strconv"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/attr"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/lib/mocks"
	cadbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
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
			attr.Roles:   "user,peer",
			attr.Revoker: "false",
			"a.b":        "val1",
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
			attr.Roles:          allRoles,
			attr.DelegateRoles:  allRoles,
			attr.Revoker:        "true",
			attr.IntermediateCA: "true",
			attr.RegistrarAttr:  "a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker",
		},
	}
	registry.Identities = append(registry.Identities, id)

	// admin4 has 'hf.Registrar.Attributes' attribute but can only register 'hf.' attributes
	id = CAConfigIdentity{
		Name:           "admin4",
		Pass:           "admin4pw",
		Type:           "user",
		Affiliation:    "org2",
		MaxEnrollments: -1,
		Attrs: map[string]string{
			attr.Roles:         "user,peer",
			attr.Revoker:       "false",
			attr.RegistrarAttr: "hf.*",
		},
	}
	registry.Identities = append(registry.Identities, id)

	err = srv.Start()
	util.FatalError(t, err, "Failed to start server")
	defer srv.Stop()

	// Enroll admin2
	client := getTestClient(rootPort)

	negativeCases(t, client)
	positiveCases(t, client)
}

func negativeCases(t *testing.T, client *Client) {
	enrollResp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin2",
		Secret: "admin2pw",
	})
	util.FatalError(t, err, "Failed to enroll 'admin2' user")
	registrar := enrollResp.Identity

	missingHfRegistrarAttr(t, registrar)

	enrollResp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin4",
		Secret: "admin4pw",
	})
	util.FatalError(t, err, "Failed to enroll 'admin4' user")
	registrar = enrollResp.Identity

	invalidAttrRequestValues(t, registrar)

	// Enroll request for admin3
	enrollResp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin3",
		Secret: "admin3pw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin3' user")
	registrar = enrollResp.Identity

	invalidAttrRequest(t, registrar)
	invalidHfRegistrarAttrRequest(t, registrar)

}

func missingHfRegistrarAttr(t *testing.T, registrar *Identity) {
	// Negative case: Registrar does not have the attribute 'hf.Registrar.Attributes'
	_, err := registrar.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  "fake.attribute",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar does not own 'hf.Registrar.Attributes'
	_, err = registrar.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}
}

func invalidAttrRequestValues(t *testing.T, registrar *Identity) {
	_, err := registrar.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.Roles,
				Value: "user,peer,client",
			},
		}),
	)
	if assert.Errorf(t, err, "Should have failed to register an identity with inappropriate values for '%s', can only register a subset", attr.Roles) {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar owns this attribute but with a value of 'false', can't register with a value of 'true'
	_, err = registrar.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.Revoker,
				Value: "true",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with an attribute that is not part of 'hf.Registrar.Attributes'") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar owns this attribute but with a value of 'false', can't register with a value of 'true'
	_, err = registrar.Register(registerTestUser("user1",
		[]api.Attribute{
			api.Attribute{
				Name:  "hf.FakeAttr",
				Value: "true",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with an attribute invalid attribute with prefix 'hf.'") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}
}

func invalidAttrRequest(t *testing.T, registrar *Identity) {
	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err := registrar.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "a.b.*",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "a.b.c.d",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "test",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user11",
		[]api.Attribute{
			api.Attribute{
				Name:  "*",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user12",
		[]api.Attribute{
			api.Attribute{
				Name:  "w.x.y.z",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user13",
		[]api.Attribute{
			api.Attribute{
				Name:  "hf.fakeAttr",
				Value: "val1",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes (hf.fakeAttr)") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}
}

func invalidHfRegistrarAttrRequest(t *testing.T, registrar *Identity) {
	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err := registrar.Register(registerTestUser("user7",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "a.b, x.y",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user7",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "a.b.c, x.y",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}

	// Negative case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user7",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "hf.Revoker",
			},
		}),
	)
	if assert.Error(t, err, "Should have failed to register an identity with inappropriate attributes, identity does not posses 'hf.Revoker'") {
		assert.Contains(t, err.Error(), strconv.Itoa(caerrors.ErrAuthorizationFailure))
	}
}

func positiveCases(t *testing.T, client *Client) {
	enrollResp, err := client.Enroll(&api.EnrollmentRequest{
		Name:   "admin3",
		Secret: "admin3pw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	registrar := enrollResp.Identity

	registerCustomAttr(t, registrar)
	registerHfRegistrarAttr(t, registrar)

	// Enroll request for admin
	enrollResp, err = client.Enroll(&api.EnrollmentRequest{
		Name:   "admin",
		Secret: "adminpw",
	})
	assert.NoError(t, err, "Failed to enroll 'admin' user")

	registrar = enrollResp.Identity

	// Positive case: Registrar's hf.Registrar.Attribute = *
	_, err = registrar.Register(registerTestUser("user14",
		[]api.Attribute{
			api.Attribute{
				Name:  "*",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Failed to register an identity with appropriate attributes")
}

func registerCustomAttr(t *testing.T, registrar *Identity) {
	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err := registrar.Register(registerTestUser("user2",
		[]api.Attribute{
			api.Attribute{
				Name:  "a.b.c",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user3",
		[]api.Attribute{
			api.Attribute{
				Name:  "testattr1",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user4",
		[]api.Attribute{
			api.Attribute{
				Name:  "x.y.*",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Failed to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user5",
		[]api.Attribute{
			api.Attribute{
				Name:  "x.y.z",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")
}

func registerHfRegistrarAttr(t *testing.T, registrar *Identity) {
	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err := registrar.Register(registerTestUser("user6",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "a.b.c, x.y.*",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user7",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "a.b.c",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user8",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "x.y.z.z",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, attr, hf.Registrar.Attributes
	_, err = registrar.Register(registerTestUser("user9",
		[]api.Attribute{
			api.Attribute{
				Name:  "attr$",
				Value: "val1",
			},
		}),
	)
	assert.NoError(t, err, "Should have succeeded to register an identity with appropriate attributes")

	// Positive case: Registrar's hf.Registrar.Attribute = a.b.c, x.y.*, testattr*, attr$, hf.Registrar.Attributes, hf.Revoker
	_, err = registrar.Register(registerTestUser("user10",
		[]api.Attribute{
			api.Attribute{
				Name:  attr.RegistrarAttr,
				Value: "x.y.z.*",
			},
		}),
	)
	assert.NoError(t, err, "Should not have failed to register appropriate command")
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
			attr.Roles: allRoles,
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
	assert.Equal(t, "org2", cadbuser.GetAffiliation(user), "Failed to set correct default affiliation for a registering userr")

	err = srv.Stop()
	assert.NoError(t, err, "Failed to start server")
}

func TestRegisterWithLDAP(t *testing.T) {
	ctxMock := new(mocks.ServerRequestContext)
	ctxMock.On("ReadBody", &api.RegistrationRequestNet{}).Return(nil)
	ctxMock.On("TokenAuthentication").Return("", nil)
	ctxMock.On("IsLDAPEnabled").Return(true)

	_, err := register(ctxMock, &CA{})
	util.ErrorContains(t, err, "72", "Failed to get back write error for registering identities with LDAP")
}
