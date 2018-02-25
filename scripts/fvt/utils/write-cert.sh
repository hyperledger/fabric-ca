#!/bin/sh
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

AUTHJSON=$1
CERTFILE="$2"
KEYFILE="$3"

test -z $AUTHJSON && AUTHJSON="$HOME/fabric-ca/client.json"
test -z $CERTFILE    && CERTFILE="/tmp/cert.${RANDOM}.pem"
test -z $KEYFILE    && KEYFILE="/tmp/key.${RANDOM}.pem"

key=$(cat  $AUTHJSON |jq '.publicSigner.key'  |sed 's/"//g')
cert=$(cat $AUTHJSON |jq '.publicSigner.cert' |sed 's/"//g')
echo $cert |base64 -d > $CERTFILE
echo $key  |base64 -d > $KEYFILE
