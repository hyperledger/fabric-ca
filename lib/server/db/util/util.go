/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hyperledger/fabric-ca/lib/caerrors"
)

var (
	dbURLRegex = regexp.MustCompile("(Datasource:\\s*)?(\\S+):(\\S+)@|(Datasource:.*\\s)?(user=\\S+).*\\s(password=\\S+)|(Datasource:.*\\s)?(password=\\S+).*\\s(user=\\S+)")
)

// Levels contains the levels of identities, affiliations, and certificates
type Levels struct {
	Identity    int
	Affiliation int
	Certificate int
	Credential  int
	RAInfo      int
	Nonce       int
}

// GetDBName gets database name from connection string
func GetDBName(datasource string) string {
	var dbName string
	datasource = strings.ToLower(datasource)

	re := regexp.MustCompile(`(?:\/([^\/?]+))|(?:dbname=([^\s]+))`)
	getName := re.FindStringSubmatch(datasource)
	if getName != nil {
		dbName = getName[1]
		if dbName == "" {
			dbName = getName[2]
		}
	}

	return dbName
}

// MaskDBCred hides DB credentials in connection string
func MaskDBCred(str string) string {
	matches := dbURLRegex.FindStringSubmatch(str)

	// If there is a match, there should be three entries: 1 for
	// the match and 9 for submatches (see dbURLRegex regular expression)
	if len(matches) == 10 {
		matchIdxs := dbURLRegex.FindStringSubmatchIndex(str)
		substr := str[matchIdxs[0]:matchIdxs[1]]
		for idx := 1; idx < len(matches); idx++ {
			if matches[idx] != "" {
				if strings.Index(matches[idx], "user=") == 0 {
					substr = strings.Replace(substr, matches[idx], "user=****", 1)
				} else if strings.Index(matches[idx], "password=") == 0 {
					substr = strings.Replace(substr, matches[idx], "password=****", 1)
				} else {
					substr = strings.Replace(substr, matches[idx], "****", 1)
				}
			}
		}
		str = str[:matchIdxs[0]] + substr + str[matchIdxs[1]:len(str)]
	}
	return str
}

// GetCADataSource returns a datasource with a unqiue database name
func GetCADataSource(dbtype, datasource string, cacount int) string {
	if dbtype == "sqlite3" {
		ext := filepath.Ext(datasource)
		dbName := strings.TrimSuffix(filepath.Base(datasource), ext)
		datasource = fmt.Sprintf("%s_ca%d%s", dbName, cacount, ext)
	} else {
		dbName := getDBName(datasource)
		datasource = strings.Replace(datasource, dbName, fmt.Sprintf("%s_ca%d", dbName, cacount), 1)
	}
	return datasource
}

// getDBName gets database name from connection string
func getDBName(datasource string) string {
	var dbName string
	datasource = strings.ToLower(datasource)

	re := regexp.MustCompile(`(?:\/([^\/?]+))|(?:dbname=([^\s]+))`)
	getName := re.FindStringSubmatch(datasource)
	if getName != nil {
		dbName = getName[1]
		if dbName == "" {
			dbName = getName[2]
		}
	}

	return dbName
}

// GetError wraps error passed in with context
func GetError(err error, getType string) error {
	if err.Error() == "sql: no rows in result set" {
		return caerrors.NewHTTPErr(404, caerrors.ErrDBGet, "Failed to get %s: %s", getType, err)
	}
	return caerrors.NewHTTPErr(504, caerrors.ErrConnectingDB, "Failed to process database request: %s", err)
}

// IsGetError returns true of if the error is for is a database get error (not found)
func IsGetError(err error) bool {
	return strings.Contains(err.Error(), strconv.Itoa(caerrors.ErrDBGet))
}
