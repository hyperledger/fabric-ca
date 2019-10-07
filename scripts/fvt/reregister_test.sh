#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils

REGISTRAR="admin"
REGIRSTRARPWD="adminpw"
USERNAME="testuser99"
HTTP_PORT="3755"
RC=0

NUM_SERVERS=4
NUM_BAD_REQ=16

while getopts "dx:" option; do
  case "$option" in
     d)   FABRIC_CA_DEBUG="true" ;;
     x)   CA_CFG_PATH="$OPTARG" ;;
  esac
done

: ${CA_CFG_PATH:="/tmp/reregister"}
: ${FABRIC_CA_DEBUG="false"}
: ${HOST="localhost:10888"}
export CA_CFG_PATH
export FABRIC_CA_CLIENT_HOME="$CA_CFG_PATH/$REGISTRAR"

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollSimpleHttp
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp 1; exit 1" INT

export FABRIC_CA_DEBUG
for driver in sqlite3 postgres mysql; do
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH -d $driver
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n $NUM_SERVERS -t rsa -l 2048 -d $driver -x $CA_CFG_PATH
   if test $? -ne 0; then
      ErrorMsg "Failed to setup fabric-ca server"
      continue
   fi

   enroll $REGISTRAR $REGIRSTRARPWD
   if test $? -ne 0; then
      ErrorMsg "Failed to enroll $REGISTRAR"
      continue
   fi

   register $REGISTRAR ${USERNAME}
   if test $? -ne 0; then
      ErrorMsg "Failed to register $USERNAME"
      continue
   fi

   for u in $(eval echo {1..$NUM_BAD_REQ}); do
      register $REGISTRAR $USERNAME
      test $? -eq 0 && ErrorMsg "Duplicate registration of $USERNAME"
   done

   $SCRIPTDIR/fabric-ca_setup.sh -L -d $driver
done
$SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH -d $driver
kill $HTTP_PID
wait $HTTP_PID
CleanUp "$RC"
exit $RC
