//go:build tools
// +build tools

/*
Copyright the Hyperledger Fabric contributors. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tools

import (
	_ "github.com/AlekSi/gocov-xml"
	_ "github.com/axw/gocov/gocov"
	_ "github.com/hyperledger/fabric/common/metrics/cmd/gendoc"
	_ "golang.org/x/lint/golint"
	_ "golang.org/x/tools/cmd/benchcmp"
	_ "golang.org/x/tools/cmd/goimports"
)
