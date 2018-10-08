/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package certificaterequest

import (
	//	"bytes"
	//	"net/http"
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/server/certificaterequest/mocks"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
)

func TestCertificateRequest(t *testing.T) {
	ctx := new(mocks.RequestContext)
	ctx.On("GetQueryParm", "id").Return("testid")
	ctx.On("GetQueryParm", "aki").Return("123456")
	ctx.On("GetQueryParm", "serial").Return("1234")
	ctx.On("GetBoolQueryParm", "notrevoked").Return(false, nil)
	ctx.On("GetBoolQueryParm", "notexpired").Return(false, nil)
	ctx.On("GetQueryParm", "ca").Return("ca1")
	ctx.On("GetQueryParm", "revoked_start").Return("2001-01-01")
	ctx.On("GetQueryParm", "revoked_end").Return("2012-12-12")
	ctx.On("GetQueryParm", "expired_start").Return("2002-02-01")
	ctx.On("GetQueryParm", "expired_end").Return("2011-11-11")

	certReq, err := NewCertificateRequest(ctx)
	assert.NoError(t, err, "failed to get certificate request")

	assert.Equal(t, "testid", certReq.GetID())
	assert.Equal(t, "123456", certReq.GetAKI())
	assert.Equal(t, "1234", certReq.GetSerial())
	assert.Equal(t, false, certReq.GetNotRevoked())
	assert.Equal(t, false, certReq.GetNotExpired())
	assert.Equal(t, "2001-01-01 00:00:00 +0000 UTC", certReq.GetRevokedTimeStart().String())
	assert.Equal(t, "2012-12-12 00:00:00 +0000 UTC", certReq.GetRevokedTimeEnd().String())
	assert.Equal(t, "2002-02-01 00:00:00 +0000 UTC", certReq.GetExpiredTimeStart().String())
	assert.Equal(t, "2011-11-11 00:00:00 +0000 UTC", certReq.GetExpiredTimeEnd().String())
}

func TestGetReq(t *testing.T) {
	ctx := new(mocks.RequestContext)
	ctx.On("GetQueryParm", "id").Return("testid")
	ctx.On("GetQueryParm", "aki").Return("123456")
	ctx.On("GetQueryParm", "serial").Return("1234")
	ctx.On("GetBoolQueryParm", "notrevoked").Return(false, nil)
	ctx.On("GetBoolQueryParm", "notexpired").Return(true, nil)
	ctx.On("GetQueryParm", "ca").Return("ca1")

	certReq, err := getReq(ctx)
	assert.NoError(t, err, "Failed to get certificate request")
	assert.NotNil(t, certReq, "Failed to get certificate request")
	assert.Equal(t, "testid", certReq.ID)
	assert.Equal(t, "123456", certReq.AKI)
	assert.Equal(t, "1234", certReq.Serial)
	assert.Equal(t, false, certReq.NotRevoked)
	assert.Equal(t, true, certReq.NotExpired)

	ctx = new(mocks.RequestContext)
	ctx.On("GetQueryParm", "id").Return("testid")
	ctx.On("GetQueryParm", "aki").Return("123456")
	ctx.On("GetQueryParm", "serial").Return("1234")
	ctx.On("GetBoolQueryParm", "notrevoked").Return(false, nil)
	ctx.On("GetQueryParm", "ca").Return("ca1")
	ctx.On("GetBoolQueryParm", "notexpired").Return(true, errors.New("failed to parse bool value"))
	certReq, err = getReq(ctx)
	util.ErrorContains(t, err, "failed to parse bool value", "should fail")

	ctx = new(mocks.RequestContext)
	ctx.On("GetQueryParm", "id").Return("testid")
	ctx.On("GetQueryParm", "aki").Return("123456")
	ctx.On("GetQueryParm", "serial").Return("1234")
	ctx.On("GetBoolQueryParm", "notexpired").Return(false, nil)
	ctx.On("GetQueryParm", "ca").Return("ca1")
	ctx.On("GetBoolQueryParm", "notrevoked").Return(true, errors.New("failed to parse bool value"))
	certReq, err = getReq(ctx)
	util.ErrorContains(t, err, "failed to parse bool value", "should fail")
}

func TestGetTimes(t *testing.T) {
	ctx := new(mocks.RequestContext)
	ctx.On("GetQueryParm", "revoked_start").Return("2001-01-01")
	ctx.On("GetQueryParm", "revoked_end").Return("2012-12-12")
	ctx.On("GetQueryParm", "expired_start").Return("2002-02-01")
	ctx.On("GetQueryParm", "expired_end").Return("2011-11-11")
	times, err := getTimes(ctx)
	assert.NoError(t, err, "Failed to get times from certificate request")
	assert.Equal(t, "2001-01-01 00:00:00 +0000 UTC", times.revokedStart.String())
	assert.Equal(t, "2012-12-12 00:00:00 +0000 UTC", times.revokedEnd.String())
	assert.Equal(t, "2002-02-01 00:00:00 +0000 UTC", times.expiredStart.String())
	assert.Equal(t, "2011-11-11 00:00:00 +0000 UTC", times.expiredEnd.String())

	ctx = new(mocks.RequestContext)
	ctx.On("GetQueryParm", "revoked_start").Return("2001-01")
	ctx.On("GetQueryParm", "revoked_end").Return("2012-12-12")
	ctx.On("GetQueryParm", "expired_start").Return("2002-02-01")
	ctx.On("GetQueryParm", "expired_end").Return("2011-11-11")
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")

	ctx = new(mocks.RequestContext)
	ctx.On("GetQueryParm", "revoked_start").Return("2001-01-01")
	ctx.On("GetQueryParm", "revoked_end").Return("2012-12-123")
	ctx.On("GetQueryParm", "expired_start").Return("2002-02-01")
	ctx.On("GetQueryParm", "expired_end").Return("2011-11-11")
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")

	ctx = new(mocks.RequestContext)
	ctx.On("GetQueryParm", "revoked_start").Return("2001-01-01")
	ctx.On("GetQueryParm", "revoked_end").Return("2012-12-12")
	ctx.On("GetQueryParm", "expired_start").Return("20023-02-01")
	ctx.On("GetQueryParm", "expired_end").Return("2011-11-11")
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")

	ctx = new(mocks.RequestContext)
	ctx.On("GetQueryParm", "revoked_start").Return("2001-01-01")
	ctx.On("GetQueryParm", "revoked_end").Return("2012-12-12")
	ctx.On("GetQueryParm", "expired_start").Return("2002-02-01")
	ctx.On("GetQueryParm", "expired_end").Return("2011-111-11")
	times, err = getTimes(ctx)
	assert.Error(t, err, "Invalid time format, should have failed")
}

func TestValidateReq(t *testing.T) {
	req := &api.GetCertificatesRequest{
		NotExpired: true,
	}
	times := &TimeFilters{
		expiredStart: &time.Time{},
	}
	err := validateReq(req, times)
	t.Log("Error: ", err)
	assert.Error(t, err, "Should have failed, both 'notexpire' and expiredStart are set")

	req = &api.GetCertificatesRequest{
		NotExpired: true,
	}
	times = &TimeFilters{
		expiredEnd: &time.Time{},
	}
	err = validateReq(req, times)
	t.Log("Error: ", err)
	assert.Error(t, err, "Should have failed, both 'notexpire' and expiredEnd are set")

	req = &api.GetCertificatesRequest{
		NotRevoked: true,
	}
	times = &TimeFilters{
		revokedStart: &time.Time{},
	}
	err = validateReq(req, times)
	t.Log("Error: ", err)
	assert.Error(t, err, "Should have failed, both 'notexpire' and revokedStart are set")

	req = &api.GetCertificatesRequest{
		NotRevoked: true,
	}
	times = &TimeFilters{
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
