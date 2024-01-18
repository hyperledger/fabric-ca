//go:build !pkcs11
// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"path"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/pkg/errors"
)

// ConfigureBCCSP configures BCCSP, using
func ConfigureBCCSP(optsPtr **factory.FactoryOpts, mspDir, homeDir string) error {
	var err error
	if optsPtr == nil {
		return errors.New("nil argument not allowed")
	}
	opts := *optsPtr
	if opts == nil {
		opts = &factory.FactoryOpts{}
	}
	if opts.Default == "" {
		opts.Default = "SW"
	}
	if strings.ToUpper(opts.Default) == "SW" {
		if opts.SW == nil {
			opts.SW = &factory.SwOpts{}
		}
		if opts.SW.Hash == "" {
			opts.SW.Hash = "SHA2"
		}
		if opts.SW.Security == 0 {
			opts.SW.Security = 256
		}
		if opts.SW.FileKeystore == nil {
			opts.SW.FileKeystore = &factory.FileKeystoreOpts{}
		}
		// The mspDir overrides the KeyStorePath; otherwise, if not set, set default
		if mspDir != "" {
			opts.SW.FileKeystore.KeyStorePath = path.Join(mspDir, "keystore")
		} else if opts.SW.FileKeystore.KeyStorePath == "" {
			opts.SW.FileKeystore.KeyStorePath = path.Join("msp", "keystore")
		}
	}
	err = makeFileNamesAbsolute(opts, homeDir)
	if err != nil {
		return errors.WithMessage(err, "Failed to make BCCSP files absolute")
	}
	log.Debugf("Initializing BCCSP: %+v", opts)
	if opts.SW != nil {
		log.Debugf("Initializing BCCSP with software options %+v", opts.SW)
	}
	*optsPtr = opts
	return nil
}
