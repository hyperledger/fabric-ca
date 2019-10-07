#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
TESTDATA="$FABRIC_CA/testdata"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
HOST="http://localhost:$PROXY_PORT"
RC=0
HOST="https://localhost:$PROXY_PORT"
. $SCRIPTDIR/fabric-ca_utils

while getopts "u:t:g:a:x:" option; do
  case "$option" in
     x)   FABRIC_HOME="$OPTARG" ;;
     u)   USERNAME="$OPTARG" ;;
     t)   USERTYPE="$OPTARG" ;;
     g)   USERGRP="$OPTARG";
          test -z "$USERGRP" && NULLGRP='true' ;;
     a)   USERATTR="$OPTARG" ;;
  esac
done

test -z "$FABRIC_HOME" && FABRIC_HOME="$HOME/fabric-ca"

: ${NULLGRP:="false"}
: ${USERNAME:="testuser"}
: ${USERTYPE:="client"}
: ${USERGRP:="bank_a"}
$($NULLGRP) && unset USERGRP
: ${USERATTR:='[{"name":"test","value":"testValue"}]'}
: ${FABRIC_CA_DEBUG="false"}

genClientConfig "$FABRIC_HOME/fabric-ca_client.json"

$FABRIC_CAEXEC client register <(echo "{
  \"id\": \"$USERNAME\",
  \"type\": \"$USERTYPE\",
  \"group\": \"$USERGRP\",
  \"attrs\": $USERATTR }") $HOST
RC=$?
exit $RC
