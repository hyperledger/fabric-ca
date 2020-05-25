/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
)

// Constants defined for the different log levels
const (
	INFO     = "info"
	WARNING  = "warning"
	DEBUG    = "debug"
	ERROR    = "error"
	FATAL    = "fatal"
	CRITICAL = "critical"
)

// SetDefaultLogLevel sets the default log level
func SetDefaultLogLevel(logLevel string, debug bool) {
	log.Debug("Set default log level: ", logLevel)
	setLogLevel(logLevel, debug, true)
}

// SetLogLevel sets the log level
func SetLogLevel(logLevel string, debug bool) error {
	log.Debug("Set log level: ", logLevel)
	return setLogLevel(logLevel, debug, false)
}

func setLogLevel(logLevel string, debug, override bool) error {
	if debug {
		if logLevel != "" && !override {
			return errors.Errorf("Can't specify log level '%s' and set debug to true at the same time", logLevel)
		} else if override {
			logLevel = "debug"
		} else if logLevel == "" {
			logLevel = "debug"
		}
	}

	switch strings.ToLower(logLevel) {
	case INFO:
		log.Level = log.LevelInfo
	case WARNING:
		log.Level = log.LevelWarning
	case DEBUG:
		log.Level = log.LevelDebug
	case ERROR:
		log.Level = log.LevelError
	case CRITICAL:
		log.Level = log.LevelCritical
	case FATAL:
		log.Level = log.LevelFatal
	default:
		log.Debug("Unrecognized log level, defaulting to 'info'")
		log.Level = log.LevelInfo
	}

	return nil
}
