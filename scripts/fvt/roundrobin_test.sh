#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
RC=0
HOST="localhost:10888"
HTTP_PORT="3755"

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp" INT

#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n4 -t rsa -l 2048 -d $driver
   test $? -ne 0 && ErrorExit "Failed to setup server"
   $SCRIPTDIR/registerAndEnroll.sh -u 'user1 user2 user3 user4 user5 user6 user7 user8 user9'
   RC=$((RC+$?))
   $SCRIPTDIR/reenroll.sh -x /tmp/keyStore/admin
   for s in 1 2 3 4; do
      curl -s http://${HOST}/ | awk -v s="server${s}" '$0~s'|html2text | egrep "HTTP|server${s}"
      verifyServerTraffic $HOST server${s} 5
      RC=$((RC+$?))
   done
   $SCRIPTDIR/fabric-ca_setup.sh -R
done
kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
