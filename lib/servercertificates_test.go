/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/caerrors"
	"github.com/hyperledger/fabric-ca/lib/mocks"
	"github.com/hyperledger/fabric-ca/lib/server/certificaterequest"
	dbutil "github.com/hyperledger/fabric-ca/lib/server/db/util"
	dbuser "github.com/hyperledger/fabric-ca/lib/server/user"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestCertificatesHandler(t *testing.T) {
	ctx := new(serverRequestContextImpl)
	req, err := http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	ctx.req = req
	_, err = certificatesHandler(ctx)
	util.ErrorContains(t, err, "No authorization header", "Failed to catch error")
}

func TestAuthChecks(t *testing.T) {
	ctxMock := new(mocks.ServerRequestContext)
	ctxMock.On("GetCaller").Return(nil, errors.New("Failed to get caller"))
	err := authChecks(ctxMock)
	util.ErrorContains(t, err, "Failed to get caller", "Expected to catch error from GetCaller() func")

	ctx := new(serverRequestContextImpl)
	user := &dbuser.Record{
		Name: "NotRegistrar",
	}
	ctx.caller = dbuser.New(user, nil)
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
	user = &dbuser.Record{
		Name:       "Registrar",
		Attributes: string(attr),
	}
	ctx.caller = dbuser.New(user, nil)
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
	user = &dbuser.Record{
		Name:       "Revoker",
		Attributes: string(attr),
	}
	ctx.caller = dbuser.New(user, nil)
	err = authChecks(ctx)
	assert.NoError(t, err, "Should not fail, caller has 'hf.Revoker' with a value of 'true' attribute")

	ctx = new(serverRequestContextImpl)
	attributes = []api.Attribute{
		api.Attribute{
			Name:  "hf.Revoker",
			Value: "false",
		},
	}
	attr, err = util.Marshal(attributes, "attributes")
	util.FatalError(t, err, "Failed to marshal attributes")
	user = &dbuser.Record{
		Name:       "NotRevoker",
		Attributes: string(attr),
	}
	ctx.caller = dbuser.New(user, nil)
	err = authChecks(ctx)
	assert.Error(t, err, "Should fail, caller has 'hf.Revoker' but with a value of 'false' attribute")
}

func TestProcessCertificateRequest(t *testing.T) {
	ctx := new(mocks.ServerRequestContext)
	ctx.On("TokenAuthentication").Return("", errors.New("Token Auth Failed"))
	err := processCertificateRequest(ctx)
	util.ErrorContains(t, err, "Token Auth Failed", "Should have failed token auth")

	ctx = new(mocks.ServerRequestContext)
	ctx.On("TokenAuthentication").Return("", nil)
	ctx.On("HasRole", "hf.Revoker").Return(errors.New("Does not have attribute"))
	attr, err := util.Marshal([]api.Attribute{}, "attributes")
	util.FatalError(t, err, "Failed to marshal attributes")
	user := &dbuser.Record{
		Name:       "NotRevoker",
		Attributes: string(attr),
	}
	ctx.On("GetCaller").Return(dbuser.New(user, nil), nil)

	err = processCertificateRequest(ctx)
	t.Log("Error: ", err)
	util.ErrorContains(t, err, fmt.Sprintf("%d", caerrors.ErrAuthorizationFailure), "Should have failed to due improper permissions")

	ctx = new(mocks.ServerRequestContext)
	ctx.On("TokenAuthentication").Return("", nil)
	ctx.On("HasRole", "hf.Revoker").Return(nil)
	ctx.On("GetCaller").Return(dbuser.New(user, nil), nil)
	req, err := http.NewRequest("POST", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get HTTP request")
	ctx.On("GetReq").Return(req)
	err = processCertificateRequest(ctx)
	t.Log("Error: ", err)
	util.ErrorContains(t, err, "Invalid request", "Should have failed to incorrect method type on HTTP request")

}

func TestProcessGetCertificateRequest(t *testing.T) {
	ctx := new(serverRequestContextImpl)
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
}

type mockHTTPWriter struct {
	http.ResponseWriter
	t *testing.T
}

// Header returns the header map that will be sent by WriteHeader.
func (m *mockHTTPWriter) Header() http.Header {
	return m.ResponseWriter.Header()
}

// WriteHeader sends an HTTP response header with status code.
func (m *mockHTTPWriter) WriteHeader(scode int) {
	m.WriteHeader(1)
}

// Write writes the data to the connection as part of an HTTP reply.
func (m *mockHTTPWriter) Write(buf []byte) (int, error) {
	w := m.ResponseWriter
	if !strings.Contains(string(buf), "certs") && !strings.Contains(string(buf), "BEGIN CERTIFICATE") && !strings.Contains(string(buf), "caname") {
		m.t.Error("Invalid response being sent back from certificates endpoint")
	}
	return w.Write(buf)
}

// Write writes the data to the connection as part of an HTTP reply.
func (m *mockHTTPWriter) Flush() {}

func TestServerGetCertificates(t *testing.T) {
	os.RemoveAll("getCertTest")
	defer os.RemoveAll("getCertTest")
	var err error

	level := &dbutil.Levels{
		Affiliation: 1,
		Identity:    1,
		Certificate: 1,
	}
	mockOperationsServer := &mocks.OperationsServer{}
	fakeCounter := &metricsfakes.Counter{}
	fakeCounter.WithReturns(fakeCounter)
	mockOperationsServer.NewCounterReturns(fakeCounter)
	fakeHistogram := &metricsfakes.Histogram{}
	fakeHistogram.WithReturns(fakeHistogram)
	mockOperationsServer.NewHistogramReturns(fakeHistogram)
	srv := &Server{
		Operations: mockOperationsServer,
		levels:     level,
	}
	ca, err := newCA("getCertTest/config.yaml", &CAConfig{}, srv, false)
	util.FatalError(t, err, "Failed to get CA")

	ctx := new(serverRequestContextImpl)
	req, err := http.NewRequest("GET", "", bytes.NewReader([]byte{}))
	util.FatalError(t, err, "Failed to get GET HTTP request")

	user := &dbuser.Record{
		Name: "NotRevoker",
	}
	ctx.caller = dbuser.New(user, nil)

	ctx.req = req
	ctx.ca = ca
	w := httptest.NewRecorder()
	ctx.resp = &mockHTTPWriter{w, t}

	err = testInsertCertificate(&certdb.CertificateRecord{
		Serial: "1111",
		AKI:    "9876",
	}, "testCertificate", ca)
	util.FatalError(t, err, "Failed to insert certificate with serial/AKI")

	err = getCertificates(ctx, &certificaterequest.Impl{})
	assert.NoError(t, err, "Should not have returned error, failed to process GET certificate request")

	mockCtx := new(mocks.ServerRequestContext)
	mockCtx.On("GetResp").Return(nil)
	mockCtx.On("GetCaller").Return(nil, errors.New("failed to get caller"))
	err = getCertificates(mockCtx, nil)
	util.ErrorContains(t, err, "failed to get caller", "did not get correct error response")

	testUser := dbuser.New(&dbuser.Record{Name: "testuser"}, nil)
	mockCtx = new(mocks.ServerRequestContext)
	mockCtx.On("GetResp").Return(nil)
	mockCtx.On("GetCaller").Return(testUser, nil)
	mockCtx.On("GetCertificates", (*certificaterequest.Impl)(nil), "").Return(nil, errors.New("failed to get certificates"))
	err = getCertificates(mockCtx, nil)
	util.ErrorContains(t, err, "failed to get certificates", "did not get correct error response")
}

func TestStoreCert(t *testing.T) {
	dir, err := ioutil.TempDir("", "testStoreCert")
	assert.NoError(t, err, "failed to create temp directory")
	defer os.RemoveAll(dir)

	cd := NewCertificateDecoder(dir)
	err = cd.StoreCert("testID", dir, []byte("testing store cert function"))
	assert.NoError(t, err, "failed to store cert")

	filePath := filepath.Join(dir, "testID.pem")
	assert.Equal(t, true, util.FileExists(filePath))

	cert, err := ioutil.ReadFile(filePath)
	assert.NoError(t, err, "failed to read certificate file")
	assert.Equal(t, "testing store cert function", string(cert))

	err = cd.StoreCert("testID", dir, []byte("testing store cert function - second cert"))
	assert.NoError(t, err, "failed to store cert")

	filePath = filepath.Join(dir, "testID-1.pem")
	assert.Equal(t, true, util.FileExists(filePath))
	cert, err = ioutil.ReadFile(filePath)
	assert.NoError(t, err, "failed to read certificate file")
	assert.Equal(t, "testing store cert function", string(cert))

	filePath = filepath.Join(dir, "testID-2.pem")
	assert.Equal(t, true, util.FileExists(filePath))
	cert, err = ioutil.ReadFile(filePath)
	assert.NoError(t, err, "failed to read certificate file")
	assert.Equal(t, "testing store cert function - second cert", string(cert))

	err = cd.StoreCert("testID", dir, []byte("testing store cert function - third cert"))
	assert.NoError(t, err, "failed to store cert")
	filePath = filepath.Join(dir, "testID-3.pem")
	assert.Equal(t, true, util.FileExists(filePath))

	// Error case - renaming a certificate file that does not exist should fail
	cd = NewCertificateDecoder(dir)
	cd.certIDCount["testID2"] = 1
	err = cd.StoreCert("testID2", dir, []byte("testing store cert function"))
	util.ErrorContains(t, err, "Failed to rename certificate", "Should have failed")
}
