#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
KEYSTORE="/tmp/keyStore"
RC=0

. $SCRIPTDIR/fabric-ca_utils

function enrollUser() {
   local USERNAME=$1
   mkdir -p $KEYSTORE/$USERNAME
   export CA_CFG_PATH=$KEYSTORE/admin
   OUT=$($SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -g $USERGRP -x $CA_CFG_PATH)
   echo "$OUT"
   PASSWD="$(echo "$OUT" | head -n1 | awk '{print $NF}')"
   export CA_CFG_PATH=$KEYSTORE/$USERNAME
   $SCRIPTDIR/enroll.sh -u $USERNAME -p $PASSWD -x $CA_CFG_PATH
   rc=$?
   return $rc
}

while getopts "du:t:k:l:" option; do
  case "$option" in
     d)   FABRIC_CA_DEBUG="true" ;;
     u)   USERNAME="$OPTARG" ;;
     t)   USERTYPE="$OPTARG" ;;
     g)   USERGRP="$OPTARG" ;;
     k)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
  esac
done

: ${FABRIC_CA_DEBUG="false"}
: ${USERNAME="newclient"}
: ${USERTYPE="client"}
: ${USERGRP="bank_a"}
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}
: ${HOST="localhost:10888"}

export FABRIC_CA_DEBUG
mkdir -p $KEYSTORE/admin
export CA_CFG_PATH=$KEYSTORE/admin
$SCRIPTDIR/enroll.sh -u admin -p adminpw -x $CA_CFG_PATH
test $? -eq 0 || ErrorExit "Failed to enroll admin"

for i in $USERNAME; do
   enrollUser $i
   RC=$((RC+$?))
   sleep 1
done

exit $RC
