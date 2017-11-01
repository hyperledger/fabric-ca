#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
export CA_CFG_PATH="/tmp/groups"

HTTP_PORT="3755"
cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollSimpleHttp
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp 1; exit 1" INT

# group is required for all identity types
$SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH -d mysql
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -d mysql
enroll
export FABRIC_CA_CLIENT_HOME="$CA_CFG_PATH/admin"
register admin user1 client bank_a
test $? -ne 0 && ErrorMsg "Failed to register user1:client:bank_a"
register admin user2 peer bank_a
test $? -ne 0 && ErrorMsg "Failed to register user2:client:bank_a"
register admin user3 client bogus
test "$?" -eq 0 && ErrorMsg "Improperly registered user3:client with 'bogus' group"
register admin user4 peer bogus
test "$?" -eq 0 && ErrorMsg "Improperly registered user4:peer with 'bogus' group"
register admin user5 validator bank_a
test $? -ne 0 && ErrorMsg "Failed to register user5:validator:bank_a"
register admin user6 auditor bank_a
test $? -ne 0 && ErrorMsg "Failed to register user6:auditor:bank_a"
register admin user7 validator bogus
test $? -eq 0 && ErrorMsg "Failed to register user7:validator:bank_a with 'bogus' group"
register admin user8 auditor bogus
test $? -eq 0 && ErrorMsg "Failed to register user8:auditor with 'bogus' group"

$SCRIPTDIR/fabric-ca_setup.sh -L -d mysql
$SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH -d mysql
rm -rf $FABRIC_CA_CLIENT_HOME
kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
