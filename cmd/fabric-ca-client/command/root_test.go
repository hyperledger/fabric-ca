/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveCommandName(t *testing.T) {
	ccmd := NewCommand("")

	testCases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "subcommand first",
			args:     []string{"enroll", "-u", "http://admin:adminpw@localhost:7054"},
			expected: "enroll",
		},
		{
			name:     "global flags before subcommand",
			args:     []string{"--loglevel", "warning", "enroll", "-u", "http://admin:adminpw@localhost:7054"},
			expected: "enroll",
		},
		{
			name:     "global flag with equals before subcommand",
			args:     []string{"--loglevel=warning", "gencsr", "--csr.cn", "identity"},
			expected: "gencsr",
		},
		{
			name:     "nested subcommand",
			args:     []string{"--loglevel", "warning", "identity", "list"},
			expected: "identity",
		},
		{
			name:     "getcacert alias",
			args:     []string{"--home", "/tmp/home", "getcacert", "-u", "http://localhost:7054"},
			expected: "getcainfo",
		},
		{
			name:     "no subcommand",
			args:     []string{"--loglevel", "warning"},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, resolveCommandName(ccmd.rootCmd, tc.args))
		})
	}
}

func TestEnrollWithGlobalFlagsBeforeSubcommand(t *testing.T) {
	adminHome := filepath.Join(tdDir, "enrolladminhomeflags")

	err := os.RemoveAll(adminHome)
	require.NoErrorf(t, err, "Failed to remove directory %s: %s", adminHome, err)
	defer os.RemoveAll(adminHome)

	srv := setupEnrollTest(t)
	defer stopAndCleanupServer(t, srv)

	err = RunMain([]string{cmdName, "--loglevel", "warning", "enroll", "-d", "-u", enrollURL, "-H", adminHome})
	require.NoError(t, err, "enroll should succeed with global flags before subcommand")
}
