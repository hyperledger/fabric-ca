#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


: ${TESTCASE:="multica-test"}
TDIR=/tmp/$TESTCASE
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
TLSDIR="$TESTDATA"
NUMINTCAS=4
MAXENROLL=$((2*NUMINTCAS))
NUMUSERS=2
RC=0

function createRootCA() {
   # Start RootCA
   mkdir -p "$TDIR/ca0"
   $SCRIPTDIR/fabric-ca_setup.sh -I -x "$TDIR/ca0" -d $driver -m $MAXENROLL
   sed -i "/^ca:/,/^[^\t ]/ s@\(\(cert\|key\)file:\).*@\1@" $TDIR/ca0/runFabricCaFvt.yaml
   FABRIC_CA_SERVER_HOME="$TDIR/ca0" fabric-ca-server start -d --cacount $NUMINTCAS \
                                      --csr.hosts $CA_HOST_ADDRESS --address $CA_HOST_ADDRESS \
                                      -c $TDIR/ca0/runFabricCaFvt.yaml 2>&1 |
                                      tee $TDIR/ca0/server.log &
   pollFabricCa "" "" $CA_DEFAULT_PORT
}

function enrollUser() {
   local user=$1
   local pswd=$2
   local caname=$3
   /usr/local/bin/fabric-ca-client enroll -d \
                   --caname $caname \
                   --mspdir $TDIR/$caname/$user/${user}msp \
                   --id.maxenrollments $MAXENROLL \
                   -u ${PROTO}$user:$pswd@$CA_HOST_ADDRESS:$CA_DEFAULT_PORT \
                   -c $TDIR/$caname/enroll.yaml \
                   $TLSOPT \
                   --csr.hosts $user@fab-client.raleigh.ibm.com,${user}.fabric.raleigh.ibm.com,127.42.42.$i
   return $?
}

function registerAndEnrollUser() {
   local user=$1
   local caname=$2
   local attrs='a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=100000'
   local rc=0
   pswd=$(eval /usr/local/bin/fabric-ca-client register -u ${PROTO}admin:adminpw@$CA_HOST_ADDRESS:$CA_DEFAULT_PORT \
                        --id.attrs "$attrs" \
                        --caname $caname \
                        --mspdir $TDIR/$caname/admin/adminmsp \
                        --id.name $user \
                        --id.type user \
                        --id.maxenrollments $MAXENROLL \
                        --id.affiliation bank_a \
                        $TLSOPT \
                        -c $TDIR/$caname/register.yaml|tail -n1 | awk '{print $NF}')
   /usr/local/bin/fabric-ca-client enroll \
                   --caname $caname \
                   --mspdir $TDIR/$caname/$user/${user}msp \
                   --id.maxenrollments $MAXENROLL \
                   -u ${PROTO}$user:$pswd@$CA_HOST_ADDRESS:$CA_DEFAULT_PORT \
                   -c $TDIR/$caname/$user/enroll.yaml \
                   $TLSOPT \
                   --csr.hosts $user@fab-client.raleigh.ibm.com,$user.fabric.raleigh.ibm.com,127.37.37.$i
   return $?
}

function reenrollUser() {
   local user=$1
   local caname=$2
   local rc=0
   /usr/local/bin/fabric-ca-client reenroll \
                      --caname $caname \
                      --mspdir $TDIR/$caname/${user}/${user}msp \
                      --id.maxenrollments $MAXENROLL \
                      -u ${PROTO}@$CA_HOST_ADDRESS:$CA_DEFAULT_PORT \
                      -c $TDIR/$caname/$user/enroll.yaml \
                      $TLSOPT \
                      --csr.hosts ${user}@fab-client.raleigh.ibm.com,${user}.fabric.raleigh.ibm.com,127.42.42.$i
   return $?
}

function revokeUser() {
   local revoker=$1
   local user=$2
   local caname=$3
   local sn=$4
   local aki=$5
   local rc=0
   test -n "$sn" && local serial="--revoke.serial $sn"
   test -n "$aki" && local index="--revoke.aki $aki"
   export FABRIC_CA_CLIENT_HOME="$TDIR/$caname/$revoker"
   /usr/local/bin/fabric-ca-client revoke --caname $caname \
               --mspdir $TDIR/$caname/$revoker/${revoker}msp \
               -u ${PROTO}$CA_HOST_ADDRESS:$CA_DEFAULT_PORT \
               --revoke.name $user $serial $index $TLSOPT
   return $?
}

function resetDB() {
  local driver=$1
  if [ $driver = "mysql" ]; then
    i=0;while test $((i++)) -lt $NUMINTCAS; do
      mysql --host=localhost --user=root --password=mysql -e "drop database fabric_ca_ca$i;"
    done
  fi

  if [ $driver = "postgres" ]; then
    i=0;while test $((i++)) -lt $NUMINTCAS; do
      psql -c "drop database fabric_ca_ca$i"
    done
  fi

  if [ $driver = "sqlite3" ]; then
    rm -rf $TDIR
  fi
}

### Start Test ###
for driver in postgres mysql; do

  # Expected codes
   # Result after enroll/reenroll -
   #    user status: 1, certs status: all 'good'
   enrolledGood=$(printf "1 %s\n%s\n%s" good good good)
   # Result after revoking the current enrollment cert -
   #    user status: 1, certs status: one revoked
   enrolledRevoked=$(printf "1 %s\n%s\n%s" good good revoked)
   # Result after revoking userid -
   #    user status: -1, certs status: all 'revoked'
   revokedRevoked=$(printf -- "-1 %s\n%s\n%s" revoked revoked revoked)

   $SCRIPTDIR/fabric-ca_setup.sh -R -x $TDIR/ca0 -D -d $driver
   rm -rf $TDIR

   resetDB $driver

   createRootCA || ErrorExit "Failed to create root CA"

   USERS=("admin" "admin2" "notadmin" "testUser" "testUser2" "testUser3" )
   PSWDS=("adminpw" "adminpw2" "pass" "user1" "user2" "user3" )
   # roundrobin through all servers in pool and enroll users
   u=-1; while test $((u++)) -lt ${#USERS[u]}; do
      i=0;while test $((i++)) -lt $NUMINTCAS; do
         for iter in $(seq 1 $MAXENROLL); do
            # Issue duplicate enroll to ensure proper processing of multiple requests
            enrollUser ${USERS[u]} ${PSWDS[u]} ca$i || ErrorExit "Failed to enroll ${USERS[u]} to ca$i"
         done
      done
   done

   # enrolling beyond the configured MAXENROLL should fail
   u=-1; while test $((u++)) -lt ${#USERS[u]}; do
      i=0;while test $((i++)) -lt $NUMINTCAS; do
         enrollUser ${USERS[u]} ${PSWDS[u]} ca$i && ErrorExit "Should have failed to enroll ${USERS[u]} to ca$i"
      done
   done

   i=0;while test $((i++)) -lt $NUMINTCAS;  do
      j=0;while test $((j++)) -lt $NUMUSERS; do
         registerAndEnrollUser user$i$j ca$i || ErrorExit "Enroll user$i$j to CA ca$i failed"
      done
   done

   # roundrobin through all servers in pool and renroll users
   for iter in {0..1}; do
      # Issue duplicate reenroll to ensure proper processing of multiple requests
      i=0;while test $((i++)) -lt $NUMINTCAS;  do
         j=0;while test $((j++)) -lt $NUMUSERS; do
            reenrollUser user$i$j ca$i || ErrorExit "reenrollUser user$i$j ca$i failed"
         done
      done
   done

   # notadmin cannot revoke
   revokeUser notadmin user11 ca1 2>&1 | egrep "Authorization failure"
   test "$?" -ne 0 && ErrorMsg "Non-revoker successfully revoked cert or failed for incorrect reason"

   # Check the DB contents
   i=0;while test $((i++)) -lt $NUMINTCAS;  do
      j=0;while test $((j++)) -lt $NUMUSERS; do
         test "$(testStatus user$i$j $driver $TDIR/ca0/ca/ca$i fabric_ca_ca$i )" = "$enrolledGood" ||
            ErrorMsg "Incorrect user/certificate status for $user$i$j" RC
      done
   done

   i=0;while test $((i++)) -lt $NUMINTCAS;  do
      j=0;while test $((j++)) -lt $NUMUSERS; do
         c="$TDIR/ca$i/user$i$j/user$i${j}msp/signcerts/cert.pem"
         # Grab the serial number of user$i$j cert
         SN_UC="$(openssl x509 -noout -serial -in $c | awk -F'=' '{print toupper($2)}')"
         # and the auth keyid of notadmin cert - translate upper to lower case
         AKI_UC=$(openssl x509 -noout -text -in $c |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print toupper($0)}')
         # Revoke the certs
         echo "SN  ---> $SN_UC"
         echo "AKI ---> $AKI_UC"
         revokeUser admin user$i$j ca$i "$SN_UC" "$AKI_UC"
         #### Ensure that revoking an already revoked cert doesn't blow up
         echo "=========================> Issuing duplicate revoke by -s -a"
         revokeUser admin user$i$j ca$i "$SN_UC" "$AKI_UC"
         test "$(testStatus user$i$j $driver $TDIR/ca0/ca/ca$i fabric_ca_ca$i )" = "$enrolledRevoked" ||
            ErrorMsg "Incorrect user/certificate status for user$i$j" RC
      done
   done

   i=0;while test $((i++)) -lt $NUMINTCAS;  do
      j=0;while test $((j++)) -lt $NUMUSERS; do
         echo "=========================> REVOKING by --eid"
         revokeUser admin user$i$j ca$i
         #### Ensure that revoking an already revoked cert doesn't blow up
         echo "=========================> Issuing duplicate revoke by -s -a"
         revokeUser admin user$i$j ca$i
         test "$(testStatus user$i$j $driver $TDIR/ca0/ca/ca$i fabric_ca_ca$i )" = "$revokedRevoked" ||
            ErrorMsg "Incorrect user/certificate status for user$i$j" RC
      done
   done

   #### Revoke admin cert
   i=0;while test $((i++)) -lt $NUMINTCAS;  do
      j=0;while test $((j++)) -lt $NUMUSERS; do
         echo "=========================> REVOKING self"
         revokeUser admin admin ca$i
         # Verify that the cert is no longer usable
         revokeUser admin user$i$j ca$i 2>&1 | egrep "Authentication failure"
         test $? -ne 0 && ErrorMsg "Improper revocation using revoked certificate" RC
      done
   done

   $SCRIPTDIR/fabric-ca_setup.sh -L -x $TDIR/ca0 -D -d $driver
   kill $(ps -x -o pid,comm | awk '$2~/fabric-ca-serve/ {print $1}')
done

# If the test failed, leave the results for debugging
test "$RC" -eq 0 && $SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH -d $driver

### Clean up ###
rm -f $TESTDATA/openssl.cnf.base.req
CleanUp "$RC"
exit $RC

