/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldap

import (
	"fmt"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

/*
func TestLDAP(t *testing.T) {
	proto := "ldap"
	port := 10389

	//dn := "uid=admin,ou=system"
	//pwd := "secret"
	dn := "cn=admin,dc=example,dc=org"
	pwd := "admin"
	//host, err := os.Hostname()
	//if err != nil {
	//	t.Errorf("testLDAP os.Hostname failed: %s", err)
	//	return
	//}
	host := "localhost"
	base := "dc=example,dc=org"
	url := fmt.Sprintf("%s://%s:%s@%s:%d/%s", proto, dn, pwd, host, port, base)
	c, err := NewClient(&Config{URL: url}, nil)
	if err != nil {
		t.Errorf("ldap.NewClient failure: %s", err)
		return
	}
	user, err := c.GetUser("jsmith", []string{"mail"})
	if err != nil {
		t.Errorf("ldap.Client.GetUser failure: %s", err)
		return
	}
	err = user.Login("jsmithpw", -1)
	if err != nil {
		t.Errorf("ldap.User.Login failure: %s", err)
	}
	path := user.GetAffiliationPath()
	if path == nil {
		t.Error("ldap.User.GetAffiliationPath is nil")
	}
	err = user.Login("bogus", -1)
	if err == nil {
		t.Errorf("ldap.User.Login passed but should have failed")
	}
	email, err := user.GetAttribute("mail")
	assert.NoError(t, err, "failed getting mail attribute")
	if email.GetValue() == "" {
		t.Errorf("ldap.User.GetAttribute failed: no mail found")
	} else {
		assert.EqualValues(t, "jsmith", email.Value)
	}
}
*/

func TestLDAPNegative(t *testing.T) {
	_, err := NewClient(nil, nil)
	if err == nil {
		t.Errorf("ldap.NewClient(nil) passed but should have failed")
	}
	_, err = NewClient(&Config{URL: "bogus"}, nil)
	if err == nil {
		t.Errorf("ldap.NewClient(bogus) passed but should have failed")
	}
	_, err = NewClient(&Config{URL: "ldaps://localhost"}, nil)
	if err != nil {
		t.Errorf("ldap.NewClient(ldaps) failed: %s", err)
	}
	_, err = NewClient(&Config{URL: "ldap://localhost:badport"}, nil)
	if err == nil {
		t.Errorf("ldap.NewClient(badport) passed but should have failed")
	}
}

/*
func TestLDAPTLS(t *testing.T) {
	proto := "ldaps"
	dn := "cn=admin,dc=example,dc=org"
	pwd := "admin"
	host := "localhost"
	base := "dc=example,dc=org"
	port := 10636
	url := fmt.Sprintf("%s://%s:%s@%s:%d/%s", proto, dn, pwd, host, port, base)
	c, err := NewClient(&Config{URL: url}, nil)
	if err != nil {
		t.Errorf("ldap.NewClient failure: %s", err)
		return
	}
	testdata := "../../../../testdata"
	c.TLS.CertFiles = []string{filepath.Join(testdata, "root.pem")}
	c.TLS.Client.CertFile = filepath.Join(testdata, "tls_client-cert.pem")
	c.TLS.Client.KeyFile = filepath.Join(testdata, "tls_client-key.pem")
	user, err := c.GetUser("jsmith", []string{"mail"})
	if err != nil {
		t.Errorf("ldap.Client.GetUser failure: %s", err)
		return
	}
	err = user.Login("jsmithpw", -1)
	if err != nil {
		t.Errorf("ldap.User.Login failure: %s", err)
	}
	path := user.GetAffiliationPath()
	if path == nil {
		t.Error("ldap.User.GetAffiliationPath is nil")
	}
	err = user.Login("bogus", -1)
	if err == nil {
		t.Errorf("ldap.User.Login passed but should have failed")
	}
	email, err := user.GetAttribute("mail")
	assert.NoError(t, err, "failed getting mail attribute")
	if email == nil {
		t.Errorf("ldap.User.GetAttribute failed: no mail found")
	} else {
		assert.EqualValues(t, "jsmith", email.Value)
	}
}
*/

// Tests String method of ldap.Config
func TestLDAPConfigStringer(t *testing.T) {
	ldapConfig := Config{
		Enabled:     true,
		URL:         "ldap://admin:adminpwd@localhost:8888/users",
		UserFilter:  "(uid=%s)",
		GroupFilter: "(memberUid=%s)",
	}
	str := fmt.Sprintf("%+v", ldapConfig) // String method of Config is called here
	t.Logf("Stringified LDAP Config: %s", str)
	assert.NotContains(t, str, "admin", "Username is not masked in the ldap URL")
	assert.NotContains(t, str, "adminpwd", "Password is not masked in the ldap URL")

	ldapConfig = Config{
		Enabled:     true,
		URL:         "ldaps://admin:adminpwd@localhost:8888/users",
		UserFilter:  "(uid=%s)",
		GroupFilter: "(memberUid=%s)",
	}
	str = fmt.Sprintf("%+v", ldapConfig)
	t.Logf("Stringified LDAP Config: %s", str)
	assert.NotContains(t, str, "admin", "Username is not masked in the ldap URL")
	assert.NotContains(t, str, "adminpwd", "Password is not masked in the ldap URL")
}

func TestUsernameEscape(t *testing.T) {
	for testName, testCase := range map[string]struct {
		Username string
		Expected string
	}{
		"wildcard":     {Username: "*", Expected: "\\2a"},
		"right parens": {Username: ")", Expected: "\\29"},
		"left parens":  {Username: "(", Expected: "\\28"},
		"backslash":    {Username: "\\", Expected: "\\5c"},
	} {
		t.Run(testName, func(t *testing.T) {
			proto := "ldap"
			dn := "cn=admin,dc=example,dc=org"
			pwd := "admin"
			host := "localhost"
			port := 10389
			base := "dc=example,dc=org"
			url := fmt.Sprintf("%s://%s:%s@%s:%d/%s", proto, dn, pwd, host, port, base)

			client, err := NewClient(&Config{URL: url}, nil)
			require.NoError(t, err, "NewClient")

			connection := NewConnectionStub(t)
			client.AdminConn = connection

			expectedFilter := fmt.Sprintf(client.UserFilter, testCase.Expected)
			searchRequestMatcher := func(req *ldap.SearchRequest) bool {
				return req.Filter == expectedFilter
			}
			searchResult := &ldap.SearchResult{
				Entries: []*ldap.Entry{
					new(ldap.Entry),
				},
			}
			connection.mock.On("Search", mock.MatchedBy(searchRequestMatcher)).Return(searchResult, nil)
			connection.mock.On("Close").Maybe().Return(nil)

			_, err = client.GetUser(testCase.Username, nil)
			require.NoError(t, err, "GetUser")

			connection.mock.AssertExpectations(t)
		})
	}
}

func NewConnectionStub(t *testing.T) *ConnectionStub {
	result := new(ConnectionStub)
	result.mock.Test(t)
	return result
}

type ConnectionStub struct {
	mock mock.Mock
}

func (c *ConnectionStub) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	args := c.mock.MethodCalled("Search", searchRequest)
	result, _ := args.Get(0).(*ldap.SearchResult)
	return result, args.Error(1)
}

func (c *ConnectionStub) Close() error {
	args := c.mock.MethodCalled("Close")
	return args.Error(0)
}
