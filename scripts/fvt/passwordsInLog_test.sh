#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

function checkPasswd() {
   local pswd="$1"
   local Type="$2"
   : ${Type:="user"}

   set -f
   # Extract password value(s) from logfile
   case "$Type" in
          user) passwd=$(egrep -o "Pass:[^[:space:]]+" $LOGFILE| awk -F':' '{print $2}') ;;
          ldap) passwd=$(egrep -io "ldap.*@" $LOGFILE| awk -v FS=[:@] '{print $(NF-1)}') ;;
         mysql) passwd=$(egrep -o "[a-z0-9*]+@tcp" $LOGFILE| awk -v FS=@ '{print $(NF-1)}') ;;
      postgres) passwd=$(egrep -o "password=[^ ]+ " $LOGFILE| awk -F '=' '{print $2}') ;;
   esac

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

function passWordSub() {
   sed -i "/datasource:/ s/\(password=\)[[:alnum:]]\+\(.*\)/\1$PSWD\2/
          s/dc=com:$LDAP_PASSWD/dc=com:$PSWD/
          s/datasource:\(.*\)mysql@/datasource:\1$PSWD@/" $TESTDIR/runFabricCaFvt.yaml
}

RC=0
: ${TESTCASE:="passwordsInLog"}
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
$SCRIPTDIR/fabric-ca_setup.sh -R;  mkdir -p $TESTDIR
$SCRIPTDIR/fabric-ca_setup.sh -I -X -n1 -D 2>&1 | tee $LOGFILE
test ${PIPESTATUS[0]} -eq 0 && checkPasswd "$PSWD" || ErrorMsg "Init of CA failed"

for server in ldap mysql postgres; do
   $SCRIPTDIR/fabric-ca_setup.sh -R; mkdir -p $TESTDIR
   case $server in
      ldap) $SCRIPTDIR/fabric-ca_setup.sh -a -I -D > $LOGFILE 2>&1 ;;
         *) $SCRIPTDIR/fabric-ca_setup.sh -I -D -d $server 2>&1 > $LOGFILE ;;
   esac
   passWordSub
   $SCRIPTDIR/fabric-ca_setup.sh -S >> $LOGFILE 2>&1
   test ${PIPESTATUS[0]} -eq 0 && checkPasswd "$PSWD" $server || ErrorMsg "Init of CA failed"
done

CleanUp $RC
exit $RC
