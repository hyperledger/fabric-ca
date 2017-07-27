#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

RC=0
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
fabric-ca-server init -b administrator:administratorpw -d &> /tmp/log.txt
grep "administratorpw" /tmp/log.txt &> /dev/null
if [ $? == 0 ]; then
   ErrorMsg "Passwords were not masked in the log"
fi
CleanUp $RC
exit $RC