/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"testing"

	"github.com/cloudflare/cfssl/log"
	"github.com/stretchr/testify/assert"
)

func TestSetDefaultLogLevel(t *testing.T) {
	SetDefaultLogLevel("warning", false)
	assert.Equal(t, log.LevelWarning, log.Level)

	SetDefaultLogLevel("warning", true)
	assert.Equal(t, log.LevelDebug, log.Level)
}

func TestDefaultLogLevel(t *testing.T) {
	err := SetLogLevel("info", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LevelInfo, log.Level)

	err = SetLogLevel("warning", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LevelWarning, log.Level)

	err = SetLogLevel("debug", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LevelDebug, log.Level)

	err = SetLogLevel("error", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LevelError, log.Level)

	err = SetLogLevel("critical", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LevelCritical, log.Level)

	err = SetLogLevel("fatal", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LevelFatal, log.Level)

	err = SetLogLevel("badLogLevel", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LevelInfo, log.Level)

	err = SetLogLevel("warning", true)
	assert.Error(t, err)
}
