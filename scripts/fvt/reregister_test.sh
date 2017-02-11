#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
KEYSTORE="/tmp/keyStore"
REGISTRAR="admin"
REGIRSTRARPWD="adminpw"
#REGISTRAR="revoker"
#REGIRSTRARPWD="revokerpw"
HTTP_PORT="3755"
RC=0

. $SCRIPTDIR/fabric-ca_utils

function enrollUser() {
   local USERNAME=$1
   mkdir -p $KEYSTORE/$USERNAME
   export CA_CFG_PATH=$KEYSTORE/$REGISTRAR
   OUT=$($SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -g $USERGRP -x $CA_CFG_PATH)
   echo "$OUT"
   PASSWD="$(echo $OUT | tail -n1 | awk '{print $NF}')"
   export CA_CFG_PATH=$KEYSTORE/$USERNAME
   $SCRIPTDIR/enroll.sh -u $USERNAME -p $PASSWD -x $CA_CFG_PATH
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
mkdir -p $KEYSTORE/$REGISTRAR
export CA_CFG_PATH=$KEYSTORE/$REGISTRAR

#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n4 -t rsa -l 2048 -d $driver
   if test $? -ne 0; then
      ErrorMsg "Failed to setup fabric-ca server"
      continue
   fi

   $SCRIPTDIR/enroll.sh -u $REGISTRAR -p $REGIRSTRARPWD -x $CA_CFG_PATH
   if test $? -ne 0; then
      ErrorMsg "Failed to enroll $REGISTRAR"
      continue
   fi

   $SCRIPTDIR/register.sh -u ${USERNAME} -t $USERTYPE -g $USERGRP -x $CA_CFG_PATH
   if test $? -ne 0; then
      ErrorMsg "Failed to register $USERNAME"
      continue
   fi

   for i in {2..8}; do
      $SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -g $USERGRP -x $CA_CFG_PATH
      test $? -eq 0 && ErrorMsg "Duplicate registration of " $USERNAME
   done

   # all servers should register = number of successful requests
   # but...it's only available when tls is disabled
   if test "$FABRIC_TLS" = 'false'; then
      for s in {1..4}; do
         verifyServerTraffic $HOST server${s} 10 "" "" lt
         test $? -eq 0 || ErrorMsg "verifyServerTraffic failed"
         sleep 1
      done
   fi

   $SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH
done
kill $HTTP_PID
wait $HTTP_PID
CleanUp "$RC"
exit $RC
