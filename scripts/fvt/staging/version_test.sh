#!/bin/bash
: ${TESTCASE="version"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
DRIVER=sqlite3
CA_CFG_PATH="/tmp/$TESTCASE"

capath="$1"
test -z "$capath" && capath=$FABRIC_CA/bin

FABRIC_CA_CLIENTEXEC="$capath/fabric-ca-client"
FABRIC_CA_SERVEREXEC="$capath/fabric-ca-server"
test -x $FABRIC_CA_CLIENTEXEC || FABRIC_CA_CLIENTEXEC="$(which fabric-ca-client)"
test -x $FABRIC_CA_SERVEREXEC || FABRIC_CA_SERVEREXEC="$(which fabric-ca-server)"
test -x $FABRIC_CA_CLIENTEXEC || FABRIC_CA_CLIENTEXEC="/usr/local/bin/fabric-ca-client"
test -x $FABRIC_CA_SERVEREXEC || FABRIC_CA_SERVEREXEC="/usr/local/bin fabric-ca-server"
test -z "$FABRIC_CA_CLIENTEXEC" -o -z "$FABRIC_CA_SERVEREXEC" && ErrorExit "Cannot find executables"

function checkVersion() {
   awk -v ver=$1 \
       -v rc=1 \
         '$1=="Version:" && $NF==ver {rc=0}
          END {exit rc}'
}

base_version=$(awk '/^[:blank:]*BASE_VERSION/ {print $NF}' Makefile)
extra_version="snapshot-$(git rev-parse --short HEAD)"
if [ "$IS_RELEASE" = "true" ]; then
   project_version=${base_version}
else
   project_version=${base_version}-${extra_version}
fi
echo "Project version is: $project_version"

trap "CleanUp 1; exit 1" INT
$FABRIC_CA_SERVEREXEC version | checkVersion "$project_version" || let RC+=1
$FABRIC_CA_CLIENTEXEC version | checkVersion "$project_version" || let RC+=1

CleanUp $RC
exit $RC
