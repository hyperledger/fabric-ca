#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
RC=0
HOST="localhost:10888"
SERVERCONFIG="/tmp/serverConfig.json"
export FABRIC_CA_HOME="$HOME/fabric-ca"
CLIENTCONFIG="$FABRIC_CA_HOME/fabric-ca/fabric-ca_client.json"
CLIENTCERT="$FABRIC_CA_HOME/cert.pem"
PKI="$SCRIPTDIR/utils/pki"

MAX_ENROLL="$1"
: ${MAX_ENROLL:="32"}
UNLIMITED=100

# default value
cat > "$SERVERCONFIG" <<EOF
{
 "tls_disable":true,
 "authentication": true,
 "driver":"sqlite3",
 "data_source":"fabric-ca.db",
 "users": {
    "admin": {
      "pass": "adminpw",
      "type": "client",
      "group": "bank_a",
      "attrs": [{"name":"hf.Registrar.Roles","value":"client,user,peer,validator,auditor"},
                {"name":"hf.Registrar.DelegateRoles", "value": "client,user,validator,auditor"},
                {"name":"hf.Revoker", "value": "true"}]
    }
 },
 "groups": {
   "banks_and_institutions": {
     "banks": ["bank_a"]
   }
 },
 "signing": {
    "default": {
       "usages": ["cert sign"],
       "expiry": "8000h",
       "ca_constraint": {"is_ca": true, "max_path_len":1},
       "ocsp_no_check": true,
       "not_before": "2016-12-30T00:00:00Z"
    },
    "expiry": {
       "usages": ["cert sign"],
       "expiry": "1s"
    }
 }
}
EOF

trap "rm $SERVERCONFIG; CleanUp" INT
# explicitly set value
   # user can only enroll MAX_ENROLL times
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -m $MAX_ENROLL
   i=0
   while test $((i++)) -lt "$MAX_ENROLL"; do
      $SCRIPTDIR/enroll.sh
      RC=$((RC+$?))
      currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
      test "$currId" == "$prevId" && RC=$((RC+1))
      prevId="$currId"
   done
   # max reached -- should fail
   $SCRIPTDIR/enroll.sh
   test "$?" -eq 0 && RC=$((RC+1))
   currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
   test "$currId" != "$prevId" && RC=$((RC+1))
   prevId="$currId"


# explicitly set value to '1'
   # user can only enroll once
   MAX_ENROLL=1
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -m $MAX_ENROLL
   i=0
   while test $((i++)) -lt "$MAX_ENROLL"; do
      $SCRIPTDIR/enroll.sh
      RC=$((RC+$?))
      currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
      test "$currId" == "$prevId" && RC=$((RC+1))
      prevId="$currId"
   done
   # max reached -- should fail
   $SCRIPTDIR/enroll.sh
   test "$?" -eq 0 && RC=$((RC+1))
   currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
   test "$currId" != "$prevId" && RC=$((RC+1))
   prevId="$currId"

# explicitly set value to '0'
   # user enrollment unlimited
   MAX_ENROLL=0
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -m $MAX_ENROLL
   i=0
   while test $((i++)) -lt "$UNLIMITED"; do
      $SCRIPTDIR/enroll.sh
      RC=$((RC+$?))
      currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
      test "$currId" == "$prevId" && RC=$((RC+1))
      prevId="$currId"
   done

# implicitly set value to '0' (default)
   # user enrollment unlimited
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -g $SERVERCONFIG
   i=0
   while test $((i++)) -lt "$UNLIMITED"; do
      $SCRIPTDIR/enroll.sh
      RC=$((RC+$?))
      currId=$($PKI -f display -c $CLIENTCERT | awk '/Subject Key Identifier:/ {getline;print $1}')
      test "$currId" == "$prevId" && RC=$((RC+1))
      prevId="$currId"
   done
rm $SERVERCONFIG
CleanUp $RC
exit $RC
