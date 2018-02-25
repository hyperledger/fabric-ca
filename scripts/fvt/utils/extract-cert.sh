#!/bin/sh
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

CLIENTCERT=$1
CLIENTKEY=$2

: ${CLIENTCERT:="$HOME/fabric-ca/cert.pem"}
: ${CLIENTKEY:="$HOME/fabric-ca/key.pem"}

#key=$(cat  $CLIENTAUTH |jq '.publicSigner.key'  |sed 's/"//g')
#cert=$(cat $CLIENTAUTH |jq '.publicSigner.cert' |sed 's/"//g')
#echo CERT:
#echo $cert |base64 -d| openssl x509 -text 2>&1 | sed 's/^/    /'
#type=$(echo $key  |base64 -d | head -n1 | awk '{print tolower($2)}')
#echo KEY:
#echo $key  |base64 -d| openssl $type -text 2>/dev/null| sed 's/^/    /'
#case $1 in
#   d) base64 -d ;;
#   *) awk -v FS='' '
#         BEGIN { printf "-----BEGIN CERTIFICATE-----\n"}
#         { for (i=1; i<=NF; i++) if (i%64) printf $i; else print $i }
#         END   { if ((i%64)!=0) print "" ; printf "-----END CERTIFICATE-----\n" }'
#      ;;
#esac
echo CERT:
openssl x509 -in $CLIENTCERT -text 2>&1 | sed 's/^/    /'
type=$(cat $CLIENTKEY | head -n1 | awk '{print tolower($2)}')
echo KEY:
openssl $type -in $CLIENTKEY -text 2>/dev/null| sed 's/^/    /'

