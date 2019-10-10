#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

function rmConfigFiles() {
   rm -rf $TESTDIR/ca-cert.pem \
          $TESTDIR/fabric-ca-server-config.yaml \
          $TESTDIR/fabric-ca-server.db $TESTDIR/msp \
          $TESTDIR/fabric-ca-cert.pem $TESTDIR/fabric_ca \
          $TESTDIR/runFabricCaFvt.yaml
}

function checkPasswd() {
   local pswd="$1"
   local Type="$2"
   : ${Type:="user"}

   set -f
   # Extract password value(s) from logfile
   case "$Type" in
          user) passwd=$(egrep -ao "Pass:[^[:space:]]+" $LOGFILE| awk -F':' '{print $2}') ;;
          ldap) passwd=$(egrep -aio "ldap.*@" $LOGFILE| awk -v FS=[:@] '{print $(NF-1)}') ;;
         mysql) passwd=$(egrep -ao "[a-z0-9*]+@tcp" $LOGFILE| awk -v FS=@ '{print $(NF-1)}') ;;
      postgres) passwd=$(egrep -ao "password=[^ ]+ " $LOGFILE| awk -F '=' '{print $2}') ;;
      register) passwd=$(egrep -oar 'Received registration.*Secret[^ ]+' $LOGFILE | awk -F':' '{print $NF}') ;;
intermediateCa) passwd=$(egrep -ao "Enrolling.*Secret:[^ ]+ " $LOGFILE | awk -F':' '{print $NF}') ;;
   esac

   # Fail if password is empty
   if [[ -z "$passwd" ]] ; then
      ErrorMsg "Unable to extract password value(s) for type $Type"
   fi

   # Fail if password matches anything other than '*'
   for p in $passwd; do
      if ! [[ "$p" =~ \*+ ]]; then
         ErrorMsg "Password '$passwd' was not masked in the log"
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
          /enrollment:/ a\    name: user\n    secret: $PSWD
          s/datasource:\(.*\)mysql@/datasource:\1$PSWD@/" $TESTDIR/runFabricCaFvt.yaml
}

function testBootstrap() {
   > $LOGFILE
   # Test using bootstrap ID
   fabric-ca-server init -b $USER:$PSWD -d 2>&1 | tee $LOGFILE
   test ${PIPESTATUS[0]} -eq 0 && checkPasswd "$PSWD" || ErrorMsg "Init of CA failed"
   cp $LOGFILE $FABRIC_CA_SERVER_HOME/testBootstrap.log
}

function testCaRegistry() {
   > $LOGFILE
   # Test using multiple IDs from pre-supplied config file
   $SCRIPTDIR/fabric-ca_setup.sh -I -X -n1 -D 2>&1 | tee $LOGFILE
   test ${PIPESTATUS[0]} -eq 0 && checkPasswd "$PSWD" || ErrorMsg "Init of CA failed"
   cp $LOGFILE $FABRIC_CA_SERVER_HOME/testCaRegistry.log
}

function testExternalServers() {
   for server in mysql postgres ldap; do
      rmConfigFiles
      case $server in
         ldap) $SCRIPTDIR/fabric-ca_setup.sh -a -I -D > $LOGFILE 2>&1 ;;
            *) $SCRIPTDIR/fabric-ca_setup.sh -I -D -d $server > $LOGFILE 2>&1 ;;
      esac
      passWordSub
      $SCRIPTDIR/fabric-ca_setup.sh -D -X -S >> $LOGFILE 2>&1
      test $? -eq 0 && checkPasswd "$PSWD" $server || ErrorMsg "Start of CA failed"
      cp $LOGFILE $FABRIC_CA_SERVER_HOME/test${server}.log
      $SCRIPTDIR/fabric-ca_setup.sh -K
   done
}

function testRegister() {
   rmConfigFiles
   $SCRIPTDIR/fabric-ca_setup.sh -D -X -I -S > $LOGFILE 2>&1
   test $? -eq 0 && checkPasswd "$PSWD" $server || ErrorMsg "Start of CA failed"
   enroll
   register
   checkPasswd "" register
   cat $LOGFILE
   cp $LOGFILE $FABRIC_CA_SERVER_HOME/testRegisterGeneratedPswd.log
   > $LOGFILE
   register "" Testuser2 "" "" "" "" "$PSWD"
   checkPasswd "$PSWD" register
   cp $LOGFILE $FABRIC_CA_SERVER_HOME/testRegisterSuppliedPswd.log
}

function testIntermediateCa() {
   FABRIC_CA_SERVER_HOME="$FABRIC_CA_SERVER_HOME/intCa1"
   LOGFILE=$TESTDIR/testIntermediateCa.log
   fabric-ca-server start --csr.hosts 127.0.0.2 --address 127.0.0.2 --port 7055 -b admin:adminpw $INTTLSOPT \
                          -u ${PROTO}intermediateCa1:intermediateCa1pw@127.0.0.1:$CA_DEFAULT_PORT -d > $LOGFILE 2>&1 &
   pollFabricCa "" 127.0.0.2 7055 || ErrorMsg "Failed to start intermediate CA"
   checkPasswd intermediateCa1pw intermediateCa
   cp $LOGFILE $FABRIC_CA_SERVER_HOME/testIntermediateCa.log
}

### Start Main Test ###
RC=0
: ${TESTCASE:="passwordsInLog"}
TESTDIR="/tmp/$TESTCASE"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
export CA_CFG_PATH="$TESTDIR"
export FABRIC_CA_SERVER_HOME="$TESTDIR"
LOGFILE=$FABRIC_CA_SERVER_HOME/log.txt

USER=administrator
PSWD=thisIs_aLongUniquePasswordWith_aMinisculePossibilityOfBeingDuplicated

$SCRIPTDIR/fabric-ca_setup.sh -R
mkdir -p $TESTDIR
testBootstrap
testCaRegistry
testExternalServers
testRegister
testIntermediateCa

CleanUp $RC
exit $RC
