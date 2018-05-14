/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseInput(t *testing.T) {
	input := "01:AA:22:bb"

	parsedInput := parseInput(input)

	assert.NotContains(t, parsedInput, ":", "failed to correctly remove colons from input")
	assert.NotEqual(t, string(parsedInput[0]), "0", "failed to correctly remove leading zeros from input")
	assert.NotContains(t, parsedInput, "AA", "failed to correctly lowercase capital letters")
}
