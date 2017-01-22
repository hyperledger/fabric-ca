#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
KEYSTORE="/tmp/keyStore"
HOST="localhost:10888"
HTTP_PORT="3755"
RC=0

. $SCRIPTDIR/fabric-ca_utils

function enrollUser() {
   local USERNAME=$1
   mkdir -p $KEYSTORE/$USERNAME
   export FABRIC_CA_HOME=$KEYSTORE/admin
   OUT=$($SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -g $USERGRP -x $FABRIC_CA_HOME)
   echo "$OUT"
   PASSWD="$(echo $OUT | tail -n1 | awk '{print $NF}')"
   export FABRIC_CA_HOME=$KEYSTORE/$USERNAME
   $SCRIPTDIR/enroll.sh -u $USERNAME -p $PASSWD -x $FABRIC_CA_HOME
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


cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp" INT

export FABRIC_CA_DEBUG
mkdir -p $KEYSTORE/admin
export FABRIC_CA_HOME=$KEYSTORE/admin

#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_HOME
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n4 -t rsa -l 2048 -d $driver
   RC=$((RC+$?))

   $SCRIPTDIR/enroll.sh -u admin -p adminpw -x $FABRIC_CA_HOME
   if test $? -ne 0; then
      echo "Failed to enroll admin"
      RC=$((RC+1))
      continue
   fi


   $SCRIPTDIR/register.sh -u ${USERNAME} -t $USERTYPE -g $USERGRP -x $FABRIC_CA_HOME
   if test $? -ne 0; then
      echo "Failed to register $USERNAME"
      RC=$((RC+1))
      continue
   fi

   for i in {2..8}; do
      $SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -g $USERGRP -x $FABRIC_CA_HOME
      if test $? -eq 0; then
         echo "Duplicate registration of " $USERNAME
         RC=$((RC+1))
      fi
   done

   for s in {1..4}; do
      verifyServerTraffic $HOST server${s} 10 "" "" lt
      RC=$((RC+$?))
      sleep 1
   done

   $SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_HOME
done
kill $HTTP_PID
wait $HTTP_PID
CleanUp "$RC"
exit $RC
