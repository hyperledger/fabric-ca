/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package runner

import (
	"time"
)

// DefaultStartTimeout is the timeout period for starting a container
const DefaultStartTimeout = 30 * time.Second

// DefaultShutdownTimeout is the timeout period for stopping a container
const DefaultShutdownTimeout = 10 * time.Second

// DefaultNamer is the default naming function.
var DefaultNamer NameFunc = UniqueName

// A NameFunc is used to generate container names.
type NameFunc func() string
