/*
Copyright IBM Corp. 2018 All Rights Reserved.

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
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestCertificatesHandler(t *testing.T) {
	log.Level = log.LevelDebug
	ctx := new(serverRequestContext)
	req, err := http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	ctx.req = req
	_, err = certificatesHandler(ctx)
	util.ErrorContains(t, err, "No authorization header", "Failed to catch error")
}

func TestAuthChecks(t *testing.T) {
	ctxMock := new(mocks.ServerRequestCtx)
	ctxMock.On("GetCaller").Return(nil, errors.New("Failed to get caller"))
	err := authChecks(ctxMock)
	util.ErrorContains(t, err, "Failed to get caller", "Expected to catch error from GetCaller() func")

	ctx := new(serverRequestContext)
	user := &UserRecord{
		Name: "NotRegistrar",
	}
	ctx.caller = newDBUser(user, nil)
	err = authChecks(ctx)
	assert.Error(t, err, "Caller does not possess the appropriate attributes to request manage certificates")

	attributes := []api.Attribute{
		api.Attribute{
			Name:  "hf.Registrar.Roles",
			Value: "peer,client",
		},
	}

	attr, err := util.Marshal(attributes, "attributes")
	util.FatalError(t, err, "Failed to marshal attributes")
	user = &UserRecord{
		Name:       "Registrar",
		Attributes: string(attr),
	}
	ctx.caller = newDBUser(user, nil)
	err = authChecks(ctx)
	assert.NoError(t, err, "Should not fail, caller has 'hf.Registrar.Roles' attribute")

	attributes = []api.Attribute{
		api.Attribute{
			Name:  "hf.Revoker",
			Value: "true",
		},
	}
	attr, err = util.Marshal(attributes, "attributes")
	util.FatalError(t, err, "Failed to marshal attributes")
	user = &UserRecord{
		Name:       "Revoker",
		Attributes: string(attr),
	}
	ctx.caller = newDBUser(user, nil)
	err = authChecks(ctx)
	assert.NoError(t, err, "Should not fail, caller has 'hf.Revoker' with a value of 'true' attribute")

	ctx = new(serverRequestContext)
	attributes = []api.Attribute{
		api.Attribute{
			Name:  "hf.Revoker",
			Value: "false",
		},
	}
	attr, err = util.Marshal(attributes, "attributes")
	util.FatalError(t, err, "Failed to marshal attributes")
	user = &UserRecord{
		Name:       "NotRevoker",
		Attributes: string(attr),
	}
	ctx.caller = newDBUser(user, nil)
	err = authChecks(ctx)
	assert.Error(t, err, "Should fail, caller has 'hf.Revoker' but with a value of 'false' attribute")
}

func TestGetReq(t *testing.T) {
	ctx := new(serverRequestContext)
	req, err := http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")

	url := req.URL.Query()
	url.Add("id", "testid")
	url.Add("aki", "123456")
	url.Add("serial", "1234")
	url.Add("notrevoked", "false")
	url.Add("notexpired", "True")
	url.Add("notactive", "tRue")
	url.Add("ca", "ca1")
	req.URL.RawQuery = url.Encode()

	ctx.req = req
	certReq, err := getReq(ctx)
	assert.NoError(t, err, "Failed to get certificate request")
	assert.NotNil(t, certReq, "Failed to get certificate request")
	assert.Equal(t, "testid", certReq.ID)
	assert.Equal(t, "123456", certReq.AKI)
	assert.Equal(t, "1234", certReq.Serial)
	assert.Equal(t, false, certReq.NotRevoked)
	assert.Equal(t, true, certReq.NotExpired)

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("notrevoked", "notfalse")
	req.URL.RawQuery = url.Encode()
	ctx.req = req
	certReq, err = getReq(ctx)
	assert.Error(t, err, "Should fail, not valid boolean value")

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("notexpired", "notfalse")
	req.URL.RawQuery = url.Encode()
	ctx.req = req
	certReq, err = getReq(ctx)
	assert.Error(t, err, "Should fail, not valid boolean value")
}

func TestGetTimes(t *testing.T) {
	ctx := new(serverRequestContext)
	req, err := http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")

	url := req.URL.Query()
	url.Add("revoked_start", "2001-01-01")
	url.Add("revoked_end", "2012-12-12")
	url.Add("expired_start", "2002-02-01")
	url.Add("expired_end", "2011-11-11")
	req.URL.RawQuery = url.Encode()

	ctx.req = req
	times, err := getTimes(ctx)
	assert.NoError(t, err, "Failed to get times from certificate request")
	assert.Equal(t, "2001-01-01 00:00:00 +0000 UTC", times.revokedStart.String())
	assert.Equal(t, "2012-12-12 00:00:00 +0000 UTC", times.revokedEnd.String())
	assert.Equal(t, "2002-02-01 00:00:00 +0000 UTC", times.expiredStart.String())
	assert.Equal(t, "2011-11-11 00:00:00 +0000 UTC", times.expiredEnd.String())

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("revoked_start", "2001-01")
	req.URL.RawQuery = url.Encode()
	ctx.req = req
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("revoked_end", "2012-12-123")
	req.URL.RawQuery = url.Encode()
	ctx.req = req
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("expired_start", "20023-02-01")
	req.URL.RawQuery = url.Encode()
	ctx.req = req
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("expired_end", "2011-111-11")
	req.URL.RawQuery = url.Encode()
	ctx.req = req
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")
}

func TestValidateReq(t *testing.T) {
	req := &api.GetCertificatesRequest{
		NotExpired: true,
	}
	times := &timeFilters{
		expiredStart: &time.Time{},
	}
	err := validateReq(req, times)
	t.Log("Error: ", err)
	assert.Error(t, err, "Should have failed, both 'notexpire' and expiredStart are set")

	req = &api.GetCertificatesRequest{
		NotExpired: true,
	}
	times = &timeFilters{
		expiredEnd: &time.Time{},
	}
	err = validateReq(req, times)
	t.Log("Error: ", err)
	assert.Error(t, err, "Should have failed, both 'notexpire' and expiredEnd are set")

	req = &api.GetCertificatesRequest{
		NotRevoked: true,
	}
	times = &timeFilters{
		revokedStart: &time.Time{},
	}
	err = validateReq(req, times)
	t.Log("Error: ", err)
	assert.Error(t, err, "Should have failed, both 'notexpire' and revokedStart are set")

	req = &api.GetCertificatesRequest{
		NotRevoked: true,
	}
	times = &timeFilters{
		revokedEnd: &time.Time{},
	}
	err = validateReq(req, times)
	t.Log("Error: ", err)
	assert.Error(t, err, "Should have failed, both 'notexpire' and revokedEnd are set")

	req = &api.GetCertificatesRequest{}
	err = validateReq(req, times)
	assert.NoError(t, err, "Should not have returned an error, failed to valided request")
}

func TestGetTime(t *testing.T) {
	_, err := getTime("")
	assert.NoError(t, err, "Failed parse time input")

	_, err = getTime("2018-01-01")
	assert.NoError(t, err, "Failed parse time input")

	_, err = getTime("+30D")
	assert.NoError(t, err, "Failed parse time input")

	_, err = getTime("+30s")
	assert.NoError(t, err, "Failed parse time input")

	_, err = getTime("2018-01-01T")
	assert.Error(t, err, "Should fail, incomplete time string")

	_, err = getTime("+30y")
	assert.Error(t, err, "Should fail, 'y' year duration not supported")

	_, err = getTime("30h")
	assert.Error(t, err, "Should fail, +/- required for duration")

	_, err = getTime("++30h")
	assert.Error(t, err, "Should fail, two plus '+' signs")
}

func TestConvertDayToHours(t *testing.T) {
	timeHours, err := convertDayToHours("+20d")
	assert.NoError(t, err, "Failed to convert days to hours")
	assert.Equal(t, "+480h", timeHours)

	timeHours, err = convertDayToHours("d")
	assert.Error(t, err, "Should fail, not a valid number")
}

func TestProcessCertificateRequest(t *testing.T) {
	ctx := new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", errors.New("Token Auth Failed"))
	err := processCertificateRequest(ctx)
	util.ErrorContains(t, err, "Token Auth Failed", "Should have failed token auth")

	ctx = new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", nil)
	ctx.On("HasRole", "hf.Revoker").Return(errors.New("Does not have attribute"))
	attr, err := util.Marshal([]api.Attribute{}, "attributes")
	util.FatalError(t, err, "Failed to marshal attributes")
	user := &UserRecord{
		Name:       "NotRevoker",
		Attributes: string(attr),
	}
	ctx.On("GetCaller").Return(newDBUser(user, nil), nil)

	err = processCertificateRequest(ctx)
	t.Log("Error: ", err)
	util.ErrorContains(t, err, fmt.Sprintf("%d", ErrAuthFailure), "Should have failed to due improper permissions")

	ctx = new(mocks.ServerRequestCtx)
	ctx.On("TokenAuthentication").Return("", nil)
	ctx.On("HasRole", "hf.Revoker").Return(nil)
	ctx.On("GetCaller").Return(newDBUser(user, nil), nil)
	req, err := http.NewRequest("POST", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get HTTP request")
	ctx.On("GetReq").Return(req)
	err = processCertificateRequest(ctx)
	t.Log("Error: ", err)
	util.ErrorContains(t, err, "Invalid request", "Should have failed to incorrect method type on HTTP request")

}

func TestProcessGetCertificateRequest(t *testing.T) {
	ctx := new(serverRequestContext)
	req, err := http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")

	url := req.URL.Query()
	url.Add("revoked_end", "2012-12-123")
	req.URL.RawQuery = url.Encode()
	ctx.req = req
	err = processGetCertificateRequest(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("notrevoked", "not_bool")
	req.URL.RawQuery = url.Encode()
	ctx.req = req

	err = processGetCertificateRequest(ctx)
	assert.Error(t, err, "Invalid boolean value, should have failed")

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")
	url = req.URL.Query()
	url.Add("revoked_end", "2012-12-12")
	url.Add("notrevoked", "true")
	req.URL.RawQuery = url.Encode()
	ctx.req = req

	err = processGetCertificateRequest(ctx)
	assert.Error(t, err, "Invalid combination of filters, should have failed")

	req, err = http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	ctx.req = req
	err = processGetCertificateRequest(ctx)
	assert.NoError(t, err, "Should not have returned error, failed to process GET certificate request")
}
