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
export CA_CFG_PATH="/tmp/ldap"

users=( admin admin2 revoker revoker2 nonrevoker nonrevoker2 notadmin expiryUser testUser testUser2 testUser3 )

$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -a -D -X -S -n1
for u in ${users[*]}; do
   export CA_CFG_PATH=/tmp/$u
   enroll $u ${u}pw
   test $? -ne 0 && ErrorMsg "Failed to register $u"
done

$SCRIPTDIR/fabric-ca_setup.sh -R
for u in ${users[*]}; do
   rm -rf /tmp/$u
done
CleanUp $RC
exit $RC
