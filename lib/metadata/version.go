/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	db "github.com/hyperledger/fabric-ca/lib/server/db/util"
	"github.com/pkg/errors"
)

// Current levels which are incremented each time there is a change which
// requires database migration
const (
	// IdentityLevel is the current level of identities
	IdentityLevel = 2
	// AffiliationLevel is the current level of affiliations
	AffiliationLevel = 1
	// CertificateLevel is the current level of certificates
	CertificateLevel = 1
)

// Version specifies fabric-ca-client/fabric-ca-server version
// It is defined by the Makefile and passed in with ldflags
var Version = "1.4.10"

// GetVersionInfo returns version information for the fabric-ca-client/fabric-ca-server
func GetVersionInfo(prgName string) string {
	if Version == "" {
		Version = "development build"
	}

	return fmt.Sprintf("%s:\n Version: %s\n Go version: %s\n OS/Arch: %s\n",
		prgName, Version, runtime.Version(),
		fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
}

// GetVersion returns the version
func GetVersion() string {
	if Version == "" {
		panic("Version is not set for fabric-ca library")
	}
	return Version
}

// Mapping of versions to levels.
// NOTE: Append new versions to this array if migration is
// required for identity, affiliation, or certificate information.
var versionToLevelsMapping = []versionLevels{
	{
		version: "0",
		levels:  &db.Levels{Identity: 0, Affiliation: 0, Certificate: 0},
	},
	{
		version: "1.1.0",
		levels:  &db.Levels{Identity: 1, Affiliation: 1, Certificate: 1},
	},
	{
		version: "1.2.0",
		levels:  &db.Levels{Identity: 1, Affiliation: 1, Certificate: 1, Credential: 1, RAInfo: 1, Nonce: 1},
	},
	{
		version: "1.3.0",
		levels:  &db.Levels{Identity: 1, Affiliation: 1, Certificate: 1, Credential: 1, RAInfo: 1, Nonce: 1},
	},
	{
		version: "1.3.1",
		levels:  &db.Levels{Identity: 2, Affiliation: 1, Certificate: 1, Credential: 1, RAInfo: 1, Nonce: 1},
	},
	{
		version: "1.4.0",
		levels:  &db.Levels{Identity: 2, Affiliation: 1, Certificate: 1, Credential: 1, RAInfo: 1, Nonce: 1},
	},
}

type versionLevels struct {
	version string
	levels  *db.Levels
}

// GetLevels returns the levels for a particular version
func GetLevels(version string) (*db.Levels, error) {
	for i := len(versionToLevelsMapping) - 1; i >= 0; i-- {
		vl := versionToLevelsMapping[i]
		cmp, err := CmpVersion(vl.version, version)
		if err != nil {
			return nil, err
		}
		if cmp >= 0 {
			return vl.levels, nil
		}
	}
	return nil, nil
}

// CmpVersion compares version v1 to v2.
// Return 0 if equal, 1 if v2 > v1, or -1 if v2 < v1.
func CmpVersion(v1, v2 string) (int, error) {
	v1strs := strs(v1)
	v2strs := strs(v2)
	m := max(len(v1strs), len(v2strs))
	for i := 0; i < m; i++ {
		v1val, err := val(v1strs, i)
		if err != nil {
			return 0, errors.WithMessage(err, fmt.Sprintf("Invalid version: '%s'", v1))
		}
		v2val, err := val(v2strs, i)
		if err != nil {
			return 0, errors.WithMessage(err, fmt.Sprintf("Invalid version: '%s'", v2))
		}
		if v1val < v2val {
			return 1, nil
		} else if v1val > v2val {
			return -1, nil
		}
	}
	return 0, nil
}

func strs(version string) []string {
	return strings.Split(strings.Split(version, "-")[0], ".")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func val(strs []string, i int) (int, error) {
	if i >= len(strs) {
		return 0, nil
	}
	str := strs[i]
	v, err := strconv.Atoi(str)
	if err != nil {
		return 0, errors.WithMessage(err, fmt.Sprintf("Invalid version format at '%s'", str))
	}
	return v, nil
}
