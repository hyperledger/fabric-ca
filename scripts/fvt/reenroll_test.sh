#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
KEYSTORE="/tmp/keyStore"
RC=0

. $SCRIPTDIR/fabric-ca_utils

function enrollUser() {
   local USERNAME=$1
   mkdir -p $KEYSTORE/$USERNAME
   export FABRIC_CA_HOME=$KEYSTORE/admin
   OUT=$($SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -g $USERGRP -x $FABRIC_CA_HOME)
   echo "$OUT"
   PASSWD="$(echo "$OUT" | head -n1 | awk '{print $NF}')"
   export FABRIC_CA_HOME=$KEYSTORE/$USERNAME
   test -d $FABRIC_CA_HOME || mkdir -p $FABRIC_CA_HOME
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

HTTP_PORT="3755"

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp" INT

export FABRIC_CA_DEBUG
mkdir -p $KEYSTORE/admin
export FABRIC_CA_HOME=$KEYSTORE/admin
test -d $FABRIC_CA_HOME || mkdir -p $FABRIC_CA_HOME

#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do
   echo ""
   echo ""
   echo ""
   echo "------> BEGIN TESTING $driver <----------"
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $KEYSTORE
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n4 -d $driver
   if test $? -ne 0; then
      echo "Failed to setup server"
      RC=$((RC+1))
      continue
   fi

   FABRIC_CA_HOME=$KEYSTORE/admin
   $SCRIPTDIR/enroll.sh -u admin -p adminpw -x $FABRIC_CA_HOME
   if test $? -ne 0; then
      echo "Failed to enroll admin"
      RC=$((RC+1))
      continue
   fi

   for i in {1..4}; do
      enrollUser user${i}
      if test $? -ne 0; then
         echo "Failed to enroll user${i}"
      else
         FABRIC_CA_HOME=$KEYSTORE/user${i}
         test -d $FABRIC_CA_HOME || mkdir -p $FABRIC_CA_HOME
         $SCRIPTDIR/reenroll.sh -x $FABRIC_CA_HOME
         if test $? -ne 0; then
            echo "Failed to reenroll user${i}"
            RC=$((RC+1))
         fi
      fi
      sleep 1
   done

   $SCRIPTDIR/reenroll.sh -x /tmp/keyStore/admin
   $SCRIPTDIR/reenroll.sh -x /tmp/keyStore/admin
   $SCRIPTDIR/reenroll.sh -x /tmp/keyStore/admin

   for s in {1..4}; do
      curl -s http://${HOST}/ | awk -v s="server${s}" '$0~s'|html2text|grep HTTP
      verifyServerTraffic $HOST server${s} 4
      if test $? -ne 0; then
         echo "Distributed traffic to server FAILED"
         RC=$((RC+1))
      fi
      sleep 1
   done
   echo "------> END TESTING $driver <----------"
   echo "***************************************"
   echo ""
   echo ""
   echo ""
   echo ""

   $SCRIPTDIR/fabric-ca_setup.sh -R -x $KEYSTORE
done
kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
