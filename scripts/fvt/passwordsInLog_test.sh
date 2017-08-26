#!/bin/bash 
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

function checkPasswd() {
   local pswd="$1"
   set -f
   # Extract password value(s) from logfile
   passwd=$(egrep -o "Pass:[^[:space:]]+" $LOGFILE| awk -F':' '{print $2}')

   # Fail if password is empty
   if [[ -z "$passwd" ]] ; then
      ErrorMsg "Unable to extract password value(s)"
   fi

   # Fail if password matches anything other than '*'
   for p in $passwd; do 
      if ! [[ "$p" =~ \*+ ]]; then
         ErrorMsg "Passwords were not masked in the log"
      fi
   done

   # ensure any string passed in doesn't appear anywhere in logfile
   if [[ -n "$pswd" ]]; then
      grep "$pswd" "$LOGFILE" && ErrorMsg "$pswd was not masked in the log"
   fi
   set +f
}

RC=0
TESTCASE="passwordsInLog"
TESTDIR="/tmp/$TESTCASE"
mkdir -p $TESTDIR

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils

export CA_CFG_PATH="$TESTDIR"
export FABRIC_CA_SERVER_HOME="$TESTDIR"
LOGFILE=$FABRIC_CA_SERVER_HOME/log.txt

USER=administrator
PSWD=thisIs_aLongUniquePasswordWith_aMinisculePossibilityOfBeingDuplicated

# Test using bootstrap ID
fabric-ca-server init -b $USER:$PSWD -d 2>&1 | tee $LOGFILE
test ${PIPESTATUS[0]} -eq 0 && checkPasswd "$PSWD" || ErrorMsg "Init of CA failed"

# Test using multiple IDs from pre-supplied config file
$SCRIPTDIR/fabric-ca_setup.sh -R
mkdir -p $TESTDIR
$SCRIPTDIR/fabric-ca_setup.sh -I -X -n1 -D 2>&1 | tee $LOGFILE 
test ${PIPESTATUS[0]} -eq 0 && checkPasswd "$PSWD" || ErrorMsg "Init of CA failed"

CleanUp $RC
exit $RC
