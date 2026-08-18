/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalConfigBCCSPKeyStorePath(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "ca.yaml")
	const body = `
ca:
  name: testca
bccsp:
  default: SW
  sw:
    hash: SHA2
    security: 256
    filekeystore:
      keystore: /custom/keys
`
	require.NoError(t, os.WriteFile(cfgFile, []byte(body), 0o644))

	cfg := &CAConfig{}
	err := UnmarshalConfig(cfg, viper.New(), cfgFile, false)
	require.NoError(t, err)
	require.NotNil(t, cfg.CSP)
	require.NotNil(t, cfg.CSP.SW)
	require.NotNil(t, cfg.CSP.SW.FileKeystore)
	require.Equal(t, "/custom/keys", cfg.CSP.SW.FileKeystore.KeyStorePath)
}

func TestUnmarshalConfigBCCSPKeyStorePathServer(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "server.yaml")
	const body = `
port: 7054
bccsp:
  default: SW
  sw:
    filekeystore:
      keystore: var/my-keystore
`
	require.NoError(t, os.WriteFile(cfgFile, []byte(body), 0o644))

	cfg := &ServerConfig{}
	err := UnmarshalConfig(cfg, viper.New(), cfgFile, true)
	require.NoError(t, err)
	require.NotNil(t, cfg.CAcfg.CSP)
	require.NotNil(t, cfg.CAcfg.CSP.SW)
	require.NotNil(t, cfg.CAcfg.CSP.SW.FileKeystore)
	require.Equal(t, "var/my-keystore", cfg.CAcfg.CSP.SW.FileKeystore.KeyStorePath)
}
