/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mysql_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMysql(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Mysql Suite")
}

//go:generate counterfeiter -o mocks/fabricCADB.go -fake-name FabricCADB .. FabricCADB

//go:generate counterfeiter -o mocks/fabricCATx.go -fake-name FabricCATx .. FabricCATx
