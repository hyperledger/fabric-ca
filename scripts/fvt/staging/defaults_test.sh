#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_EXEC="$FABRIC_CA/bin/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
DST_KEY=$TESTDATA/ec-key.pem
DST_CERT=$TESTDATA/ec.pem
RUNCONFIG=$TESTDATA/testconfig.json
FABRIC_PID=""
. $SCRIPTDIR/fabric-ca_utils
RC=0

function startFabricCa() {
   local start=$SECONDS
   local timeout=8
   local now=0
   # if not explcitly set, use default
   if test -n "$1"; then
      local server_addr="-address $1"
      local addr=$1
   fi
   if test -n "$2"; then
      local server_port="-port $2"
      local port="$2"
   fi

   $FABRIC_EXEC server start $server_addr $server_port -ca $DST_CERT -ca-key $DST_KEY -config $RUNCONFIG &
   FABRIC_PID=$!
   until test "$started" = "${addr-127.0.0.1}:${port-$CA_DEFAULT_PORT}" -o "$now" -gt "$timeout"; do
      started="$(ss -ltnp src "${addr-127.0.0.1}:${port-$CA_DEFAULT_PORT}" | awk 'NR!=1 {print $4}')"
      sleep .5
      let now+=1
   done
   test "$started" = "${addr-127.0.0.1}:${port-$CA_DEFAULT_PORT}" && return 0 || return 1
}

startFabricCa
test $? -ne 0 && ErrorMsg "Server start default addr/port failed"
kill $FABRIC_PID
wait $FABRIC_PID

startFabricCa 127.0.0.2 3755
test $? -ne 0 && ErrorMsg "Server start user-defined addr/port failed"
echo $?
kill $FABRIC_PID
wait $FABRIC_PID

CleanUp $RC
exit $RC
