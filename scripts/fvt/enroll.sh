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

while getopts "du:p:t:l:x:" option; do
  case "$option" in
     d)   FABRIC_CA_DEBUG="true" ;;
     x)   CA_CFG_PATH="$OPTARG" ;;
     u)   USERNAME="$OPTARG" ;;
     p)   USERPSWD="$OPTARG" ;;
     t)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
  esac
done
test -z "$CA_CFG_PATH" && CA_CFG_PATH="$HOME/fabric-ca"
test -f "$CA_CFG_PATH" || mkdir -p $CA_CFG_PATH

: ${FABRIC_CA_DEBUG="false"}
: ${USERNAME="admin"}
: ${USERPSWD="adminpw"}
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}

test "$KEYTYPE" = "ecdsa" && sslcmd="ec"

test -d "$CA_CFG_PATH/$USERNAME" || mkdir -p $CA_CFG_PATH/$USERNAME
cat > $CA_CFG_PATH/$USERNAME/fabric-ca-client-config.yaml <<EOF
csr:
  cn: $USERNAME
  keyrequest:
    algo: $KEYTYPE
    size: $KEYLEN
EOF

$FABRIC_CA_CLIENTEXEC enroll -u "http://$USERNAME:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME
RC=$?
CLIENTCERT="$CA_CFG_PATH/$USERNAME/msp/signcerts/cert.pem"
lastkey=$(ls -crtd $CA_CFG_PATH/$USERNAME/msp/keystore/* | tail -n1)
test -n "$lastkey" && CLIENTKEY="$lastkey" || CLIENTKEY="$CA_CFG_PATH/$USERNAME/msp/keystore/key.pem"
$($FABRIC_CA_DEBUG) && printAuth "$CLIENTCERT" "$CLIENTKEY"
exit $RC
