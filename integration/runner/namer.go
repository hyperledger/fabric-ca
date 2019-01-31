package runner

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

// UniqueName generates a random string for a Docker containers name
func UniqueName() string {
	rname := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, rname)
	if err != nil {
		panic(fmt.Sprintf("Error generating random name: %s", err))
	}
	name := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rname)
	return strings.ToLower(name)
}
