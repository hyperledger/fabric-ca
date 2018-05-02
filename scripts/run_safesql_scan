#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -o pipefail
: ${TESTCASE:="safesql"}
TESTDIR="/tmp/$TESTCASE"
LOG="/tmp/$TESTCASE/log.txt"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0

mkdir -p $TESTDIR

safesql -v ../cmd/fabric-ca-client ../cmd/fabric-ca-server > $LOG 2>&1
grep "You're safe from SQL injection!" $LOG || ErrorMsg "$TESTCASE failed"
cat $LOG

CleanUp $RC
exit $RC
