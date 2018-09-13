#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTNAME:=ldap}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDIR="/tmp/$TESTNAME"
. $SCRIPTDIR/fabric-ca_utils
RC=0
export CA_CFG_PATH="$TESTDIR"
export UDIR="$TESTDIR/users"

rm -rf $UDIR
mkdir -p $UDIR

users1=( rootadmin admin admin2 notadmin tstadmin devadmin revoker2 revoker nonrevoker expiryUser testUser testUser2 testUser6 testUser8 )
users2=( testUser3 )

$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -a -D -X -S -n1

checkUserCert() {
   local USER="$1"
   case $USER in
     *User*|not*|non*) revoker='false' ;;
     *) revoker='true' ;;
   esac
   attrOID="1.2.3.4.5.6.7.8.1"
   # Make sure the "dn" attribute is in the user's certificate
   CERTFILE=$UDIR/$USER/msp/signcerts/cert.pem
   ATTRS=$(openssl x509 -noout -text -in $CERTFILE| awk '/'"$attrOID"'/ {getline; print $1}')
   EXPECTED="{\"attrs\":{\"hf.Revoker\":\"$revoker\",\"uid\":\"$USER\"}}"
   if test "$ATTRS" != "$EXPECTED"; then
      ErrorMsg "Failed to find hf.Revoker and uid attributes in certificate for user $USER"
      echo "   Found: $ATTRS"
      echo "   Expected: $EXPECTED"
   fi
}

revokeEcert() {
   admin="$1"
   user="$2"
   result="$3"

   certFile=$UDIR/$user/msp/signcerts/cert.pem
   AKI=$(openssl x509 -noout -text -in $certFile |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print toupper($0)}')
   SN=$(openssl x509 -noout -serial -in $certFile | awk -F'=' '{print toupper($2)}')

   case "$result" in
      pass) echo "User '$admin' is revoking the ecert of user cert of user '$user' ..."
            $FABRIC_CA_CLIENTEXEC revoke -u $URI -a $AKI -s $SN $TLSOPT -H $UDIR/$admin 2>&1
            test "$?" -eq 0 || ErrorMsg "User '$admin' failed to revoke '$user'"
      ;;
      fail) echo "User '$admin is attempting to revoke the ecert of user cert of user '$user' ..."
# Caller does not have authority to act on affiliation
            #$FABRIC_CA_CLIENTEXEC revoke -u $URI -a $AKI -s $SN $TLSOPT -H $UDIR/$admin 2>&1| grep 'does not have authority to revoke'
            $FABRIC_CA_CLIENTEXEC revoke -u $URI -a $AKI -s $SN $TLSOPT -H $UDIR/$admin 2>&1| egrep "(does not have authority to (act|revoke)|Authorization failure)"
            test "$?" -eq 0 || ErrorMsg "User '$admin' not authorized to revoke '$user'"
      ;;
    esac
}

for u in ${users1[*]}; do
   CA_CFG_PATH=$UDIR enroll $u ${u}pw uid,hf.Revoker
   test $? -ne 0 && ErrorExit "Failed to enroll $u"
   checkUserCert $u
done

$FABRIC_CA_CLIENTEXEC register -d -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT \
                           --id.name "testldapuser" \
                           -c /tmp/ldap/users/testUser8/fabric-ca-client-config.yaml 2>&1 | egrep "Registration is not supported when using LDAP"
test $? -ne 0 && ErrorExit "Registration while using LDAP should have failed"
# Sleep for more than the idle connection timeout limit of 1 second
sleep 3

for u in ${users2[*]}; do
   CA_CFG_PATH=$UDIR enroll $u ${u}pw uid,hf.Revoker
   test $? -ne 0 && ErrorExit "Failed to enroll $u"
   checkUserCert $u
done

URI=$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT

# User 'revoker' revokes the ecert of user 'testUser'
revokeEcert revoker testUser pass
# User 'admin2' revokes the ecert of user 'testUser2'
revokeEcert admin2 expiryUser pass
# User 'notadmin' not authorized to revoke (non hf.Revoker)
revokeEcert notadmin nonrevoker fail

# User 'rootadmin' (uid=rootadmin,dc=example,dc=com) can revoke all affiliations
for user in testUser2 testUser6 testUser8; do
   revokeEcert rootadmin $user pass
done
# re-enroll for next test
for u in expiryUser testUser testUser2 testUser6 testUser8; do
   CA_CFG_PATH=$UDIR enroll $u ${u}pw uid,hf.Revoker
   test $? -ne 0 && ErrorExit "Failed to enroll $u"
done

# User 'tstadmin' (uid=tstadmin,ou=tst,ou=fabric,dc=hyperledeger,dc=example,dc=com)
# can only revoke members of the 'tst' group
revokeEcert tstadmin testUser6 pass
for user in testUser2 testUser8 ; do
   revokeEcert tstadmin $user fail
done
# re-enroll for next test
for u in testUser2 testUser6 testUser8; do
   CA_CFG_PATH=$UDIR enroll $u ${u}pw uid,hf.Revoker
   test $? -ne 0 && ErrorExit "Failed to enroll $u"
done

# User 'devadmin' (uid=devadmin,ou=dev,ou=fabric,dc=hyperledeger,dc=example,dc=com)
# can only revoke members of the 'dev' group
revokeEcert devadmin testUser8 pass
for user in testUser2 testUser6 ; do
   revokeEcert devadmin $user fail
done

# User 'admin' can generate crl'
echo "User 'admin' is generating a crl ... "
$FABRIC_CA_CLIENTEXEC gencrl -u $URI -H $UDIR/admin $TLSOPT
test "$?" -eq 0 || ErrorMsg "User 'admin' failed to generate a crl"
# User 'notadmin' cannot generate crl'
echo "User 'notadmin' is attempting to generate a crl ... "
$FABRIC_CA_CLIENTEXEC gencrl -u $URI -H $UDIR/notadmin $TLSOPT 2>&1| grep 'Authorization failure'
test "$?" -eq 0 || ErrorMsg "User 'notadmin' should not generate a crl"

export LDAP_ERROR=true
$SCRIPTDIR/fabric-ca_setup.sh -R
$SCRIPTDIR/fabric-ca_setup.sh -I -a -D -X -S -n1
CA_CFG_PATH=$UDIR enroll testUser testUserpw uid,hf.Revoker 2>&1 | grep "Failed to evaluate LDAP expression"
test "$?" -eq 0 || ErrorMsg "Enroll should fail, incorrect LDAP converter specified"

CleanUp $RC
exit $RC
