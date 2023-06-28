//go:build arm64 && !generic

/*
Copyright IBM Corp. All Rights Reserved.
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kilic

import _ "unsafe"

//go:linkname mul github.com/kilic/bls12-381.mul
func mul(c, a, b *Fe)
