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

TDIR=intermediateca-tests

mkdir -p $TDIR/root
cd $TDIR/root
fabric-ca-server start -b admin:adminpw -d > server.log 2>&1&
cd ../..
sleep 1

mkdir -p $TDIR/int1
cd $TDIR/int1
fabric-ca-server start -b admin:adminpw -u http://admin:adminpw@localhost:7054 -p 7055 -d > server.log 2>&1&
cd ../..
sleep 1

fabric-ca-client getcacert -u http://admin:adminpw@localhost:7055
test $? -ne 0 && ErrorExit "Failed to talk to intermediate CA1"

fabric-ca-server init -b admin:adminpw -u http://admin:adminpw@localhost:7055 -d
test $? -eq 0 && ErrorExit "CA2 should have failed to initialize"

$SCRIPTDIR/fabric-ca_setup.sh -R

CleanUp $RC
exit $RC
