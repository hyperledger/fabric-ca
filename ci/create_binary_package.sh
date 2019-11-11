#!/bin/bash
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
set -eu -o pipefail

make "release/${TARGET}"
cd "release/${TARGET}/bin"
tar -czvf "${TARGET}-${RELEASE}.tar.gz" "fabric-ca-client"
