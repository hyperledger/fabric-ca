#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
RC=0
HTTP_PORT="3755"

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp" INT
#
$($FABRIC_TLS) && TLS="-T"
# group is required if the type is client or peer.
$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X $TLS
export FABRIC_CA_HOME=/tmp/keyStore/admin
$SCRIPTDIR/enroll.sh -u admin -p adminpw
$SCRIPTDIR/register.sh -u user1 -t client -g bank_a
test $? -ne 0 && ErrorMsg "Failed to register user1:client:bank_a"
$SCRIPTDIR/register.sh -u user2 -t peer -g bank_a
test $? -ne 0 && ErrorMsg "Failed to register user2:client:bank_a"
$SCRIPTDIR/register.sh -u user3 -t client -g bogus
test "$?" -eq 0 && ErrorMsg "Improperly registered user3:client with 'bogus' group"
$SCRIPTDIR/register.sh -u user4 -t peer -g bogus
test "$?" -eq 0 && ErrorMsg "Improperly registered user4:peer with 'bogus' group"

# group is not required if the type is validator or auditor.
$SCRIPTDIR/register.sh -u user5 -t validator -g bank_a
test $? -ne 0 && ErrorMsg "Failed to register user5:validator:bank_a"
$SCRIPTDIR/register.sh -u user6 -t auditor -g bank_a
test $? -ne 0 && ErrorMsg "Failed to register user6:auditor:bank_a"
$SCRIPTDIR/register.sh -u user7 -t validator -g bogus
test $? -ne 0 && ErrorMsg "Failed to register user7:validator:bank_a with 'bogus' group"
$SCRIPTDIR/register.sh -u user8 -t auditor -g bogus
test $? -ne 0 && ErrorMsg "Failed to register user8:auditor with 'bogus' group"

# however, one is expected to at least sumbit a group with request
$SCRIPTDIR/register.sh -u user9 -t auditor -g ''
test "$?" -eq 0 && ErrorMsg "Improperly registered user9:auditor with null group"
kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
