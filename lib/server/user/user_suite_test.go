/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package user_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestUser(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "User Suite")
}

//go:generate counterfeiter -o mocks/result.go -fake-name Result . result

type result interface {
	LastInsertId() (int64, error)
	RowsAffected() (int64, error)
}
