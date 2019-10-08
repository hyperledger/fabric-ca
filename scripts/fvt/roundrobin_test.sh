#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
HOST="127.0.0.1:10888"
RC=0
HTTP_PORT="3755"
CA_CFG_PATH="/tmp/fabric-ca/roundrobin"
NUM_SERVERS=4
USER_SERVER_RATIO=8
for u in $(eval echo {1..$((NUM_SERVERS*USER_SERVER_RATIO-1))}); do
   USERS[u]="user$u"
done
NUM_USERS=${#USERS[*]}
EXPECTED_DISTRIBUTION=$(((NUM_USERS+1)*2/$NUM_SERVERS))
export CA_CFG_PATH

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollSimpleHttp
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp 1; exit 1" INT

for driver in sqlite3 mysql postgres ; do
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n $NUM_SERVERS -t rsa -l 2048 -d $driver
   test $? -ne 0 && ErrorExit "Failed to setup server"
   $SCRIPTDIR/registerAndEnroll.sh -u "${USERS[*]}"
   test $? -ne 0 && ErrorMsg "registerAndEnroll failed"
   reenroll admin
   $SCRIPTDIR/fabric-ca_setup.sh -L
done
$SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH
kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
