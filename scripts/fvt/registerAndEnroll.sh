#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0

while getopts "du:t:k:l:x:" option; do
  case "$option" in
     u)   USERNAME="$OPTARG" ;;
     t)   USERTYPE="$OPTARG" ;;
     g)   USERGRP="$OPTARG" ;;
     k)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
     x)   CA_CFG_PATH="$OPTARG" ;;
  esac
done

: ${REGISTRAR:="admin"}
: ${CA_CFG_PATH:="/tmp/fabric-ca"}
: ${USERNAME="newclient"}
: ${USERTYPE="client"}
: ${USERGRP="bank_a"}
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}

FABRIC_CA_CLIENT_HOME=$CA_CFG_PATH/$REGISTRAR
enroll
test $? -eq 0 || ErrorExit "Failed to enroll admin"

for i in $USERNAME; do
   pswd=$(register $REGISTRAR $i $USERTYPE $USERGRP "" $FABRIC_CA_CLIENT_HOME |
                                   tail -n1 | awk '{print $NF}')
   enroll $i $pswd
   RC=$((RC+$?))
done

exit $RC
