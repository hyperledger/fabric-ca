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
#
# group is required if the type is client or peer.
$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X
export FABRIC_CA_HOME=/tmp/keyStore/admin
$SCRIPTDIR/enroll.sh -u admin -p adminpw -x /tmp/keyStore/admin
$SCRIPTDIR/register.sh -u user1 -t client -g bank_a
RC=$((RC+$?))
$SCRIPTDIR/register.sh -u user2 -t peer -g bank_a
RC=$((RC+$?))
$SCRIPTDIR/register.sh -u user3 -t client -g bogus
test "$?" -eq 0 && RC=$((RC+1))
$SCRIPTDIR/register.sh -u user4 -t peer -g bogus
test "$?" -eq 0 && RC=$((RC+1))

# group is not required if the type is validator or auditor.
$SCRIPTDIR/register.sh -u user5 -t validator -g bank_a
RC=$((RC+$?))
$SCRIPTDIR/register.sh -u user6 -t auditor -g bank_a
RC=$((RC+$?))
$SCRIPTDIR/register.sh -u user7 -t validator -g bogus
RC=$((RC+$?))
$SCRIPTDIR/register.sh -u user8 -t auditor -g bogus
RC=$((RC+$?))

# however, one is expected to at least sumbit a group with request
$SCRIPTDIR/register.sh -u user9 -t auditor -g ''
test "$?" -eq 0 && RC=$((RC+1))
kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
