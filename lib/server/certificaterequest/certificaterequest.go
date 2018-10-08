/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package certificaterequest

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/pkg/errors"
)

// CertificateRequest defines the properties of a certificate request
type CertificateRequest interface {
	GetID() string
	GetSerial() string
	GetAKI() string
	GetNotRevoked() bool
	GetNotExpired() bool
	GetRevokedTimeStart() *time.Time
	GetRevokedTimeEnd() *time.Time
	GetExpiredTimeStart() *time.Time
	GetExpiredTimeEnd() *time.Time
}

// RequestContext describes the request
type RequestContext interface {
	GetQueryParm(string) string
	GetBoolQueryParm(string) (bool, error)
}

// Impl defines the properties of a certificate request
type Impl struct {
	ID               string
	SerialNumber     string
	Aki              string
	Notexpired       bool
	Notrevoked       bool
	ExpiredTimeStart *time.Time
	ExpiredTimeEnd   *time.Time
	RevokedTimeStart *time.Time
	RevokedTimeEnd   *time.Time
}

// TimeFilters defines the various times that can be used as filters
type TimeFilters struct {
	revokedStart *time.Time
	revokedEnd   *time.Time
	expiredStart *time.Time
	expiredEnd   *time.Time
}

// NewCertificateRequest returns a certificate request object
func NewCertificateRequest(ctx RequestContext) (*Impl, error) {

	// Convert time string to time type
	times, err := getTimes(ctx)
	if err != nil {
		return nil, err
	}

	// Parse the query paramaters
	req, err := getReq(ctx)
	if err != nil {
		return nil, err
	}

	// Check to make sure that the request does not have conflicting filters
	err = validateReq(req, times)
	if err != nil {
		return nil, err
	}

	return &Impl{
		ID:               req.ID,
		SerialNumber:     req.Serial,
		Aki:              req.AKI,
		Notexpired:       req.NotExpired,
		Notrevoked:       req.NotRevoked,
		ExpiredTimeStart: times.expiredStart,
		ExpiredTimeEnd:   times.expiredEnd,
		RevokedTimeStart: times.revokedStart,
		RevokedTimeEnd:   times.revokedEnd,
	}, nil
}

// GetID returns the enrollment id filter value
func (c *Impl) GetID() string {
	return c.ID
}

// GetSerial returns the serial number filter value
func (c *Impl) GetSerial() string {
	return c.SerialNumber
}

// GetAKI returns the AKI filter value
func (c *Impl) GetAKI() string {
	return c.Aki
}

// GetNotExpired returns the notexpired bool value
func (c *Impl) GetNotExpired() bool {
	return c.Notexpired
}

// GetNotRevoked returns the notrevoked bool value
func (c *Impl) GetNotRevoked() bool {
	return c.Notrevoked
}

// GetExpiredTimeStart returns the starting expiration time filter value
func (c *Impl) GetExpiredTimeStart() *time.Time {
	return c.ExpiredTimeStart
}

// GetExpiredTimeEnd returns the ending expiration time filter value
func (c *Impl) GetExpiredTimeEnd() *time.Time {
	return c.ExpiredTimeEnd
}

// GetRevokedTimeStart returns the starting revoked time filter value
func (c *Impl) GetRevokedTimeStart() *time.Time {
	return c.RevokedTimeStart
}

// GetRevokedTimeEnd returns the ending revoked time filter value
func (c *Impl) GetRevokedTimeEnd() *time.Time {
	return c.RevokedTimeEnd
}

// getTimes take the string input from query parameters and parses the
// input and generates time type response
func getTimes(ctx RequestContext) (*TimeFilters, error) {
	times := &TimeFilters{}
	var err error

	times.revokedStart, err = getTime(ctx.GetQueryParm("revoked_start"))
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid 'revoked_begin' value")
	}

	times.revokedEnd, err = getTime(ctx.GetQueryParm("revoked_end"))
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid 'revoked_end' value")
	}

	times.expiredStart, err = getTime(ctx.GetQueryParm("expired_start"))
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid 'expired_begin' value")
	}

	times.expiredEnd, err = getTime(ctx.GetQueryParm("expired_end"))
	if err != nil {
		return nil, errors.WithMessage(err, "Invalid 'expired_end' value")
	}

	return times, nil
}

// Converts string to time type
func getTime(timeStr string) (*time.Time, error) {
	log.Debugf("Convert time string (%s) to time type", timeStr)
	var err error

	if timeStr == "" {
		return nil, nil
	}

	if strings.HasPrefix(timeStr, "+") || strings.HasPrefix(timeStr, "-") {
		timeStr = strings.ToLower(timeStr)

		if strings.HasSuffix(timeStr, "y") {
			return nil, errors.Errorf("Invalid time format, year (y) is not supported, please check: %s", timeStr)
		}

		currentTime := time.Now().UTC()

		if strings.HasSuffix(timeStr, "d") {
			timeStr, err = convertDayToHours(timeStr)
		}

		dur, err := time.ParseDuration(timeStr)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse duration")
		}
		newTime := currentTime.Add(dur)

		return &newTime, nil
	}

	if !strings.Contains(timeStr, "T") {
		timeStr = timeStr + "T00:00:00Z"
	}

	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to parse time based on RFC3339")
	}

	return &parsedTime, nil
}

func convertDayToHours(timeStr string) (string, error) {
	log.Debugf("Converting days to hours: %s", timeStr)

	re := regexp.MustCompile("\\d+")
	durationValDays, err := strconv.Atoi(re.FindString(timeStr))
	if err != nil {
		return "", errors.Errorf("Invalid time format, integer values required for duration, please check: %s", timeStr)
	}
	durationValHours := 24 * durationValDays
	timeStr = string(timeStr[0]) + strconv.Itoa(durationValHours) + "h"

	log.Debug("Duration value in hours: ", timeStr)
	return timeStr, nil
}

// validateReq checks to make sure the request does not contain conflicting filters
func validateReq(req *api.GetCertificatesRequest, times *TimeFilters) error {
	if req.NotExpired && (times.expiredStart != nil || times.expiredEnd != nil) {
		return errors.New("Can't specify expiration time filter and the 'notexpired' filter")
	}

	if req.NotRevoked && (times.revokedStart != nil || times.revokedEnd != nil) {
		return errors.New("Can't specify revocation time filter and the 'notrevoked' filter")
	}

	return nil
}

// getReq will examine get the query parameters and populate the GetCertificateRequest
// struct, which makes it easier to pass around
func getReq(ctx RequestContext) (*api.GetCertificatesRequest, error) {
	var err error
	req := new(api.GetCertificatesRequest)

	req.ID = ctx.GetQueryParm("id")
	req.Serial = ctx.GetQueryParm("serial")
	req.AKI = ctx.GetQueryParm("aki")
	req.NotRevoked, err = ctx.GetBoolQueryParm("notrevoked")
	if err != nil {
		return nil, err
	}
	req.NotExpired, err = ctx.GetBoolQueryParm("notexpired")
	if err != nil {
		return nil, err
	}

	return req, nil
}
