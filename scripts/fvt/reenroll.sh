# !/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
TESTDATA="$FABRIC_CA/testdata"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
CSR="$TESTDATA/csr.json"
HOST="http://localhost:$PROXY_PORT"
RUNCONFIG="$TESTDATA/postgres.json"
INITCONFIG="$TESTDATA/csr_ecdsa256.json"
RC=0
HOST="https://localhost:$PROXY_PORT"

. $SCRIPTDIR/fabric-ca_utils

: ${FABRIC_CA_DEBUG="false"}

while getopts "k:l:x:" option; do
  case "$option" in
     x)   CA_CFG_PATH="$OPTARG" ;;
     k)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
  esac
done

: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}
: ${FABRIC_CA_DEBUG="false"}
test -z "$CA_CFG_PATH" && CA_CFG_PATH=$HOME/fabric-ca
CLIENTCERT="$CA_CFG_PATH/cert.pem"
CLIENTKEY="$CA_CFG_PATH/key.pem"
export CA_CFG_PATH

genClientConfig "$CA_CFG_PATH/client-config.json"
$FABRIC_CAEXEC client reenroll $HOST <(echo "{
    \"hosts\": [
        \"admin@fab-client.raleigh.ibm.com\",
        \"fab-client.raleigh.ibm.com\",
        \"127.0.0.2\"
    ],
    \"key\": {
        \"algo\": \"$KEYTYPE\",
        \"size\": $KEYLEN
    },
    \"names\": [
        {
            \"O\": \"Hyperledger\",
            \"O\": \"Fabric\",
            \"OU\": \"FABRIC_CA\",
            \"OU\": \"FVT\",
            \"STREET\": \"Miami Blvd.\",
            \"DC\": \"peer\",
            \"UID\": \"admin\",
            \"L\": \"Raleigh\",
            \"L\": \"RTP\",
            \"ST\": \"North Carolina\",
            \"C\": \"US\"
        }
    ]
}")
RC=$?
$($FABRIC_CA_DEBUG) && printAuth $CLIENTCERT $CLIENTKEY
exit $RC
