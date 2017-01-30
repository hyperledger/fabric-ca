#!/bin/bash
num=$1
: ${num:=1}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -X -S -n $num
