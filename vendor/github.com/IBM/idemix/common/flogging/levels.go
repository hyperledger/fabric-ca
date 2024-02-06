/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package flogging

import (
	"fmt"
	"math"

	"go.uber.org/zap/zapcore"
)

const (
	// DisabledLevel represents a disabled log level. Logs at this level should
	// never be emitted.
	DisabledLevel = zapcore.Level(math.MinInt8)

	// PayloadLevel is used to log the extremely detailed message level debug
	// information.
	PayloadLevel = zapcore.Level(zapcore.DebugLevel - 1)
)

// NameToLevel converts a level name to a zapcore.Level.  If the level name is
// unknown, zapcore.InfoLevel is returned.
func NameToLevel(level string) zapcore.Level {
	l, err := nameToLevel(level)
	if err != nil {
		return zapcore.InfoLevel
	}
	return l
}

func nameToLevel(level string) (zapcore.Level, error) {
	switch level {
	case "PAYLOAD", "payload":
		return PayloadLevel, nil
	case "DEBUG", "debug":
		return zapcore.DebugLevel, nil
	case "INFO", "info":
		return zapcore.InfoLevel, nil
	case "WARNING", "WARN", "warning", "warn":
		return zapcore.WarnLevel, nil
	case "ERROR", "error":
		return zapcore.ErrorLevel, nil
	case "DPANIC", "dpanic":
		return zapcore.DPanicLevel, nil
	case "PANIC", "panic":
		return zapcore.PanicLevel, nil
	case "FATAL", "fatal":
		return zapcore.FatalLevel, nil

	case "NOTICE", "notice":
		return zapcore.InfoLevel, nil // future
	case "CRITICAL", "critical":
		return zapcore.ErrorLevel, nil // future

	default:
		return DisabledLevel, fmt.Errorf("invalid log level: %s", level)
	}
}

func IsValidLevel(level string) bool {
	_, err := nameToLevel(level)
	return err == nil
}
