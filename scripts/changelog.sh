#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

{
  echo "## $2"
  date
  git log "$1..HEAD"  --oneline \
    | grep -v Merge \
    | sed -e 's,\[\(FABC\?-[0-9]*\)\],\[\1\](https://jira.hyperledger.org/browse/\1\),' -e 's,\([0-9|a-f]*\),* \[\1\](https://github.com/hyperledger/fabric-ca/commit/\1),'
  echo
} >> CHANGELOG.new
cat CHANGELOG.md >> CHANGELOG.new
mv -f CHANGELOG.new CHANGELOG.md
