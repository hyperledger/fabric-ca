#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
KEYSTORE="/tmp/keyStore"
HTTP_PORT="3755"
RC=0

. $SCRIPTDIR/fabric-ca_utils

function enrollUser() {
   local USERNAME=$1
   local USERTYPE=$2
   local ATTR=$3
   mkdir -p $KEYSTORE/$USERNAME
   export FABRIC_CA_HOME=$KEYSTORE/$REGISTRAR
   OUT=$($SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -a "$ATTR" -x $FABRIC_CA_HOME)
   echo "$OUT"
   PASSWD="$(echo $OUT | tail -n1 | awk '{print $NF}')"
   echo "PASSWD: $PASSWD"
   export FABRIC_CA_HOME=$KEYSTORE/$USERNAME
   $SCRIPTDIR/enroll.sh -u $USERNAME -p $PASSWD -x $FABRIC_CA_HOME
}

function registerUser() {
   local USERNAME=$1
   local USERTYPE=$2
   local ATTR=$3
   mkdir -p $KEYSTORE/$USERNAME
   export FABRIC_CA_HOME=$KEYSTORE/$REGISTRAR
   $SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -a "$ATTR" -x $FABRIC_CA_HOME 2>&1
   test $? -ne 0 && return 1
}


cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollSimpleHttp
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp" INT

REGISTRAR="admin"
REGIRSTRARPWD="adminpw"
export FABRIC_CA_DEBUG
mkdir -p $KEYSTORE/$REGISTRAR
export FABRIC_CA_HOME=$KEYSTORE/$REGISTRAR

#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_HOME
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -d $driver
   if test $? -ne 0; then ErrorMsg "server setup failed"; continue; fi
   $SCRIPTDIR/enroll.sh -u $REGISTRAR -p $REGIRSTRARPWD -x $FABRIC_CA_HOME
   if test $? -ne 0; then ErrorMsg  "Failed to enroll $REGISTRAR" continue; fi


   for DEL in client peer validator auditor; do
      # admin can enroll anybody
      REGISTRAR="admin"
      enrollUser A_$DEL $DEL "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${DEL}\"},{\"name\":\"hf.Registrar.DelegateRoles\", \"value\": \"${DEL}\"}]"
      if test $? -ne 0; then ErrorMsg "enroll A_$DEL failed"; continue; fi
      enrollUser Aleaker_$DEL $DEL "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${DEL}\"}]"
      if test $? -ne 0; then ErrorMsg "enroll Aleaker_$DEL failed"; continue; fi

      for REG in client peer validator auditor; do
         # A_$DEL can enroll and/or delegate $DEL
         REGISTRAR="Aleaker_$DEL"
         enrollUser Dleaker_$DEL$REG $REG  "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${REG}\"},{\"name\":\"hf.Registrar.DelegateRoles\", \"value\": \"${REG}\"}]"
         test $? -eq 0 && ErrorMsg "Aleaker_$DEL enrolled a delegate"
         REGISTRAR="A_$DEL"
         enrollUser D_$DEL$REG $REG  "[{\"name\":\"hf.Registrar.Roles\",\"value\":\"${REG}\"}]"
         rc=$?
         if test "$REG" == "$DEL" -a $rc -ne 0; then ErrorMsg "register D_$DEL$REG failed"
         elif test "$REG" != "$DEL" -a $rc -eq 0; then ErrorMsg "register D_$DEL$REG succeeded"
         elif test "$REG" != "$DEL" -a $rc -ne 0; then continue; fi
         for ENR in client peer validator auditor; do
            # D_$DEL$REG can enroll only $REG
            REGISTRAR="D_$DEL$REG"
            enrollUser E_$DEL$REG$ENR $ENR
            rc=$?
            if test "$REG" == "$ENR" -a $rc -ne 0; then ErrorMsg "register E_$DEL$REG$ENR failed"
            elif test "$REG" != "$ENR" -a $rc -eq 0; then ErrorMsg "register E_$DEL$REG$ENR succeeded"
            elif test "$REG" != "$ENR" -a $rc -ne 0; then continue; fi
            for XXX in client peer validator auditor; do
               # E_$DEL$REG$ENR can't enroll anyone
               REGISTRAR="E_$DEL$REG$ENR"
               registerUser X_$DEL$REG$ENR$XXX $XXX "[{\"name\":\"type\",\"value\":\"value\"}]"
               if test $? -eq 0; then ErrorMsg "X_$XXX registered a user"; continue; fi
            done
         done
      done
   done
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_HOME
done
kill $HTTP_PID
wait $HTTP_PID
CleanUp "$RC"
exit $RC
