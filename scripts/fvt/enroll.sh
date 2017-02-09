#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
TESTDATA="$FABRIC_CA/testdata"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
HOST="http://localhost:8888"
RC=0

while getopts "du:p:t:l:x:" option; do
  case "$option" in
     d)   FABRIC_CA_DEBUG="true" ;;
     x)   FABRIC_CA_HOME="$OPTARG" ;;
     u)   USERNAME="$OPTARG" ;;
     p)   USERPSWD="$OPTARG"
          test -z "$USERPSWD" && AUTH=false
     ;;
     t)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
  esac
done
test -z "$FABRIC_CA_HOME" && FABRIC_CA_HOME="$HOME/fabric-ca"
test -z "$CLIENTCERT" && CLIENTCERT="$FABRIC_CA_HOME/cert.pem"
test -z "$CLIENTKEY" && CLIENTKEY="$FABRIC_CA_HOME/key.pem"
test -f "$FABRIC_CA_HOME" || mkdir -p $FABRIC_CA_HOME

: ${FABRIC_CA_DEBUG="false"}
: ${AUTH="true"}
: ${USERNAME="admin"}
: ${USERPSWD="adminpw"}
$($AUTH) || unset USERPSWD
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}

test "$KEYTYPE" = "ecdsa" && sslcmd="ec"


genClientConfig "$FABRIC_CA_HOME/client-config.json"
$FABRIC_CAEXEC client enroll "$USERNAME" "$USERPSWD" "$HOST" <(echo "{
    \"hosts\": [
        \"admin@fab-client.raleigh.ibm.com\",
        \"fab-client.raleigh.ibm.com\",
        \"127.0.0.2\"
    ],
    \"CN\": \"$USERNAME\",
    \"key\": {
        \"algo\": \"$KEYTYPE\",
        \"size\": $KEYLEN
    },
    \"names\": [
        {
            \"SerialNumber\": \"$USERNAME\",
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
