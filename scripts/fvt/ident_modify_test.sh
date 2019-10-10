#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE="ident_modify"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
TESTDIR=/tmp/$TESTCASE
RC=0
NUMROLES=8

# defaults
declare -A defaultValues
defaultValues=([Maxenrollments]=2147483647 [Affiliation]='.' [Type]="user" [Passwd]="user1pw")

adminTemplate='
   {\"secret\": \"$passwd\",
   \"type\": \"user\",
   \"affiliation\": \"$org\",
   \"max_enrollments\": 100,
   \"attrs\":
   [{\"name\": \"hf.Registrar.Roles\", \"value\": \"client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange\"},
    {\"name\": \"hf.Registrar.DelegateRoles\", \"value\": \"client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange\"},
    {\"name\": \"hf.Revoker\", \"value\": \"true\"},
    {\"name\": \"hf.IntermediateCA\", \"value\": \"true\"},
    {\"name\": \"hf.GenCRL\", \"value\": \"true\"},
    {\"name\": \"hf.Registrar.Attributes\", \"value\": \"*\"}]}
'

function registerEnroll() {
   roles="role$1"
   utype="type$1"
   eval $FABRIC_CA_CLIENTEXEC identity add userType$i $URI --secret userType${i}pw \
      -H $TESTDIR/admin --type $roles --affiliation ${defaultValues[Affiliation]} \
      --maxenrollments ${defaultValues[Maxenrollments]} --attrs '"hf.Registrar.Roles=$roles"'
   enroll userType$i userType${i}pw
}

function checkDefaults() {
   awk -v c=0 -v e=0 \
       -v i="Name: $1," \
       -v t="Type: ${defaultValues[Type]}," \
       -v a="Affiliation: " \
       -v n="ECert:true" '
      $0~i     {c++}
      $0~t     {c++}
      $0~a     {c++}
      $0~n     {e++}
      END      {print "defaults:"c",ecert:"e;if ((c!=3)||(e!=3)) exit 1} '
}

function getAttrs() {
   # The complete (current) list
   #   hf.Affiliation
   #   hf.EnrollmentID
   #   hf.GenCRL
   #   hf.IntermediateCA
   #   hf.Registrar.Attributes
   #   hf.Registrar.DelegateRoles
   #   hf.Registrar.Roles
   #   hf.Revoker
   #   hf.Type
   local admin="$1"
   local user="$2"

   $FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/$admin 2>&1 |
     grepPrint "^Name: $user," |
     grep -oP "Attributes:.*?]"|
     tr '{' "\n" |
     grep hf| sort | awk 'BEGIN {print ""}; {print $1" "$2}'
}

function testAuthenticationAuthorization() {
   # Objective:
   # Only an authorized user can issue the list command:
   #   1 -admin will have a certificate from an unknown CA
   #   2- testUser does not have the "hf.Registrar.Roles" attribute

   rm -rf $TESTDIR/admin/msp/keystore/*
   rm -rf $TESTDIR/admin/msp/signcerts/*
   /etc/hyperledger/fabric-ca/pki -f newcert -t ec -l 256 \
      -n "/CN=admin/" -p admin >/dev/null 2>&1
   mv /root/admincert.pem $TESTDIR/admin/msp/signcerts/cert.pem
   mv /root/adminkey.pem $TESTDIR/admin/msp/keystore/key.pem
   enroll testUser user1
   for op in list remove add modify; do
      # username not required for 'list' operation
      test "$op" != list && user=testUser3 || user=""

      # Unknown CA
      $FABRIC_CA_CLIENTEXEC identity $op $user $URI -d -H $TESTDIR/admin 2>&1 |
         # @TODO these messages need to change
         # grepPrint "Authorization failure" || ErrorMsg "Test '$op' Authorization"
         grepPrint "Authentication failure" || ErrorMsg "Test '$op' Authorization"
      # testUser not authorized - user must have the "hf.Registrar.Roles" attribute
      $FABRIC_CA_CLIENTEXEC identity $op $user $URI -d -H $TESTDIR/testUser 2>&1 |
         # @TODO these messages need to change
         # grepPrint "403 Forbidden" || ErrorMsg "Test '$op' Authorization"
         grepPrint "Authorization failure" || ErrorMsg "Test '$op' Authorization"
   done
}

function testRoleAuthorization() {
   # Objective:
   # for add/modify:
   #   identity type must be in the client user's hf.Registrar.Roles list
   # for list:
   #   only entries whose type is in the "hf.Registrar.Roles attribute of
   #   the issuer will be displayed
   # Enroll admin
   enroll
   # Baseline
   $FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/admin ||
     ErrorMsg "admin 'identity list' failed"
   # the type of the identity being added must be in the user's hf.Registrar.Roles list
   $FABRIC_CA_CLIENTEXEC identity add userType1 $URI -H $TESTDIR/admin \
        --type account --affiliation ${defaultValues[Affiliation]} 2>&1 |
           grepPrint "Registrar does not have authority to act on type 'account'" ||
           ErrorMsg "admin should not be able to add user of type 'account'"
   $FABRIC_CA_CLIENTEXEC identity modify admin $URI -H $TESTDIR/admin/ -d \
      --attrs '"hf.Registrar.Roles=client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange"'
   for i in  $(seq $NUMROLES); do
      registerEnroll $i
      # only entries whose type is in the "hf.Registrar.Roles"
      # attribute of the issuer will be displayed; in this case, himself
      test $($FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/userType$i 2>&1 | wc -l) -eq 1 ||
         ErrorMsg "userType$i 'identity list' failed"
      $FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/userType$i 2>&1 |
         grepPrint "hf.EnrollmentID Value:userType$i.*Type Value:role$i.*Affiliation Value: " ||
            ErrorMsg "ID:userType$i Type:role$i 'identity list' failed"
   done
}

function testModifyRegistrarRoles() {
   # Objective:
   # Use case:
   #  a) registrar does not have <type> in hf.Registrar.Roles: fail
   #  b) registrar's entry is successfully modified to add <type>
   #  c) registrar successfully adds user with <type>

   # should fail
   $FABRIC_CA_CLIENTEXEC identity modify userType1 $URI -d \
     -H $TESTDIR/admin2 --type client 2>&1 |
        grepPrint "Authorization failure" ||
           ErrorMsg "admin2 should not be able to modify user whose type is 'role1'"
   $FABRIC_CA_CLIENTEXEC identity modify admin2 $URI -d -H $TESTDIR/admin \
      --attrs '"hf.Registrar.Roles=client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange"' ||
      ErrorMsg "modify of admin2 by admin failed"

   # should succeed
   $FABRIC_CA_CLIENTEXEC identity modify userType1 $URI -d \
      -H $TESTDIR/admin2 --type client ||
        ErrorMsg "admin2 modify of userType1 failed"

   # put it back like it was
   $FABRIC_CA_CLIENTEXEC identity modify userType1 $URI -d \
      -H $TESTDIR/admin2 --type role1 ||
         ErrorMsg "admin2 modify of userType1 failed"
}

function testAffiliation() {
   # Objective:
   # - a client may not view records outside of his own affiliation

   $FABRIC_CA_CLIENTEXEC identity modify admin $URI -d \
      -H $TESTDIR/admin --affiliation 'org2.department2'
   # User can only see himself
   test $($FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/admin 2>&1 | wc -l) -eq 1 ||
      ErrorMsg "admin 'identity list' failed"
   $FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/admin 2>&1 |
      grep  "Name: admin, Type: client, Affiliation: org2.department2" ||
         ErrorMsg "admin 'identity list' failed"
   # add a subset of roles - user can only see that explicit list
   $FABRIC_CA_CLIENTEXEC identity modify admin $URI -d -H $TESTDIR/admin2 \
      --affiliation ${defaultValues[Affiliation]} \
      --attrs '"hf.Registrar.Roles=role1,role2,role3,role4,role5,role6,role7,role8"'
   test "$($FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/admin | wc -l)" -eq $NUMROLES ||
      ErrorMsg "admin 'identity list' contained wrong number of users"
   # put it back like it was
   $FABRIC_CA_CLIENTEXEC identity modify admin $URI -d -H $TESTDIR/admin2 \
      --affiliation ${defaultValues[Affiliation]} \
      --attrs '"hf.Registrar.Roles=client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange,ca"'
}

function testDelegation () {
   # Objective:
   # an admin may not delegate roles not in his hf.Registrar.Roles,
   # even if he has a wildcarded hf.Registrar.Attributes '*'

   enroll
   # @TODO change return code to 403
   # $FABRIC_CA_CLIENTEXEC identity add userType10 $URI -d -H $TESTDIR/admin --type role1 --affiliation ${defaultValues[Affiliation]} --attrs '"hf.Registrar.DelegateRoles=type10"' | grepPrint "403 Forbidden" || ErrorMsg "admin should not be able to add user with type 'type10', or wrong error code"
   $FABRIC_CA_CLIENTEXEC identity add userType10 $URI -d -H $TESTDIR/admin \
      --type role1 --affiliation ${defaultValues[Affiliation]} \
      --attrs '"hf.Registrar.DelegateRoles=type10"' 2>&1 |
         grepPrint "not authorized to register" ||
            ErrorMsg "admin should not be able to add user with type 'type10', or wrong error code"
restrictedAdminAttrsAttrs='
   {
      "secret": "superUserpw",
      "type": "user",
      "affiliation": ".",
      "attrs": [
         {"name": "hf.Registrar.Roles", "value": "client,user,validator,auditor"},
         {"name": "hf.Registrar.Attributes", "value": "*"}
       ]
   }'
   # Create restrictedAdmin, but with hf.Registrar.Attributes: "*"
   $FABRIC_CA_CLIENTEXEC identity add restrictedAdmin $URI -d \
      --json "$restrictedAdminAttrsAttrs" -H $TESTDIR/admin 2>&1
   pw=superUserpw
   enroll restrictedAdmin $pw
   $FABRIC_CA_CLIENTEXEC identity list $URI -d --id restrictedAdmin -H $TESTDIR/restrictedAdmin
   if test "$?" -ne 0; then
      ErrorMsg "Failed to enroll restrictedAdmin"
      return
   fi

   # Attempting to create user with greater authority than restrictedAdmin should fail
SuperAttrs='
   {"secret": "superUserpw",
   "type": "user",
   "affiliation": ".",
   "max_enrollments": -1,
   "attrs":
   [{"name": "hf.Registrar.Roles", "value": "pianist,SuperUser,client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange"},
    {"name": "hf.Registrar.DelegateRoles", "value": "SuperUser,client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange"},
    {"name": "hf.Revoker", "value": "true"},
    {"name": "hf.IntermediateCA", "value": "true"},
    {"name": "hf.GenCRL", "value": "true"},
    {"name": "hf.Registrar.Attributes", "value": "*"}]}'
   $FABRIC_CA_CLIENTEXEC identity add SuperUser $URI -d \
      --json "$SuperAttrs" -H $TESTDIR/restrictedAdmin 2>&1 |
         grepPrint "attribute value:.*is not a member" ||
            ErrorMsg "restrictedAdmin should not be able to add SuperUser, or wrong error code"
}

function testDefaults() {
   # Objective:
   # ensure the correct defaults for 'add'
   $FABRIC_CA_CLIENTEXEC identity add vanillaUser $URI -H $TESTDIR/admin 2>&1 |
     tr '{' "\n" |
        checkDefaults vanillaUser ||
           ErrorMsg "Incorrect default values for new user"
}

function testHfAttrs() {
   # Objective:
   # add a user with every available configurable
   #  parameter an enure all values are set correctly

   local admin="admin"
   local user="everythingBagel"

   org=org1
   passwd=${defaultValues[Passwd]}
   eval "userDef=\"$adminTemplate\""
   $FABRIC_CA_CLIENTEXEC identity add $user $URI --json "$userDef" -H $TESTDIR/$admin 2>&1
   enroll $user $passwd
   expectedAttrs="
Name:hf.Affiliation Value:$org
Name:hf.EnrollmentID Value:$user
Name:hf.GenCRL Value:true
Name:hf.IntermediateCA Value:true
Name:hf.Registrar.Attributes Value:*
Name:hf.Registrar.DelegateRoles Value:client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange
Name:hf.Registrar.Roles Value:client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange
Name:hf.Revoker Value:true
Name:hf.Type Value:user"
   getAttrs $admin $user
   currentAttrs="$(getAttrs $admin $user)"
   if test "$currentAttrs" != "$expectedAttrs"; then
      ErrorMsg "Incorrect value for registered attributes"
      echo "currentAttrs: $currentAttrs"
      echo "expectedAttrs: $expectedAttrs"
      return
   fi
}

function testLateralAffiliation() {
   # Objective:
   # Ensure that an admin may only add/modify a user
   #  in his own affiliation tree, e.g. not disjunct (lateral)
   #  and not higher in the tree

   # now that we have an admin within an org, attempt to register new user in same org
   local admin="everythingBagel"
   local user="NewUserOrg1"
   org=org1
   eval "userDef=\"$adminTemplate\""
   $FABRIC_CA_CLIENTEXEC identity add $user $URI -d \
      --json "$userDef" -H $TESTDIR/$admin 2>&1 ||
         ErrorMsg "Failed to add user '$user'"
   enroll $user $passwd || ErrorMsg "Failed to enroll user '$user'"
   # attempt to modify user in same org
   $FABRIC_CA_CLIENTEXEC identity modify $user $URI -d \
      -H $TESTDIR/$admin --affiliation ${defaultValues[Affiliation]} \
      --attrs '"hf.Registrar.Roles=client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange,ca"' 2>&1 |
         grepPrint "Authorization failure" || ErrorMsg "$admin should not be able to operate on higher level affiliation ${defaultValues[Affiliation]}"

   # register new user in child org
   admin="NewUserOrg1"
   user="NewUserOrg1Dep1"
   org=org1.department1
   eval "userDef=\"$adminTemplate\""
   $FABRIC_CA_CLIENTEXEC identity add $user $URI -d \
      --json "$userDef" -H $TESTDIR/$admin 2>&1 ||
         ErrorMsg "Failed to add user '$user'"
   enroll $user $passwd || ErrorMsg "Failed to enroll user '$user'"

   # register new user in same org
   admin="NewUserOrg1Dep1"
   user="NewUser2Org1Dep1"
   org=org1.department1
   eval "userDef=\"$adminTemplate\""
   $FABRIC_CA_CLIENTEXEC identity add $user $URI -d\
      --json "$userDef" -H $TESTDIR/$admin 2>&1 ||
         ErrorMsg "Failed to add user '$user'"
   enroll $user $passwd || ErrorMsg "Failed to enroll user '$user'"
   # modify user in same org
   $FABRIC_CA_CLIENTEXEC identity modify $user $URI -d -H $TESTDIR/$admin \
      --attrs "hf.IntermediateCA=false" 2>&1 ||
         ErrorMsg "Failed to modify user '$user'"
   # restrict hf.Registrar.Attributes for admin
   $FABRIC_CA_CLIENTEXEC identity modify $admin $URI -d -H $TESTDIR/$admin \
      --attrs "hf.Registrar.Attributes=hf*" 2>&1 ||
      ErrorMsg "Failed to modify user '$admin'"
   # attempt to modify w/ wildarded hf.Registrar.Attributes
   $FABRIC_CA_CLIENTEXEC identity modify $user $URI -d -H $TESTDIR/$admin \
      --attrs "hf.IntermediateCA=true" 2>&1 ||
         ErrorMsg "Failed to modify user '$user'"
   # take away entirely hf.Registrar.Attributes from admin
   $FABRIC_CA_CLIENTEXEC identity modify $admin $URI -d -H $TESTDIR/admin \
      --attrs "hf.Registrar.Attributes=''" 2>&1 ||
         ErrorMsg "Failed to modify user '$admin'"
   # attempt to modify w/o hf.Registrar.Attributes set
   # this returns 'Authorization failure' should return '403 Forbidden'
   $FABRIC_CA_CLIENTEXEC identity modify $user $URI -d -H $TESTDIR/$admin \
      --attrs "hf.IntermediateCA=false" 2>&1 |
         grepPrint "Authorization failure" ||
            ErrorMsg "admin '$admin' w/o hf.Registrar.Attributes should not be able to modify user '$user', or wrong error code"

   # attempt to register new user in lateral org
   admin="NewUser2Org1Dep1"
   user="NewUserOrg1Dep2"
   org=org1.department2
   eval "userDef=\"$adminTemplate\""
   $FABRIC_CA_CLIENTEXEC identity add $user $URI -d --json "$userDef" -H $TESTDIR/$admin 2>&1 |
      grepPrint "Caller does not have authority to act on affiliation '$org'" ||
         ErrorMsg "Incorrectly added '$user', or improper error message"

   # attempt to register higher affiliation
   admin="NewUser2Org1Dep1"
   user="NewUser1Org1"
   org=org1
   eval "userDef=\"$adminTemplate\""
   $FABRIC_CA_CLIENTEXEC identity add $user $URI -d --json "$userDef" -H $TESTDIR/$admin 2>&1 |
      grepPrint "Caller does not have authority to act on affiliation '$org'" ||
         ErrorMsg "Incorrectly added '$user', or improper error message"
}

function testConflictingHfAttrs() {
   # Objective:
   #   Ensure that we cannot set 'static' internal attributes:
   #     hf.Type
   #     hf.EnrollmentID
   local admin="$1"
   local user="$2"
   userdef='
   {"secret": "user1pw",
   "type": "orange",
   "affiliation": "org1",
   "max_enrollments": 1,
   "attrs":
   [ {"name": "hf.Type", "value": "apple"}]}
   '
   for flag in  '--type peer' '--affiliation .' '--attrs a=1' '--maxenrollments 1' '--secret p' '--type app'; do
      $FABRIC_CA_CLIENTEXEC identity add $user $URI -d $flag --json "$userdef" \
         -H $TESTDIR/$admin 2>&1 | grep -o "Can't use 'json' flag" ||
         ErrorMsg "Failed invalid flag combination"
   done

   $FABRIC_CA_CLIENTEXEC identity add ${user}1 $URI -d --json "$userdef" -H $TESTDIR/$admin 2>&1 |
         grepPrint "Cannot register fixed value attribute 'hf.Type'" ||
            ErrorMsg "Should not be able to set hf.Type against '--type'"

   userdef='
   {"name": "admin",
   "type": "user",
   "affiliation": "org1",
   "max_enrollments": 1,
   "attrs":
   [ {"name": "hf.EnrollmentID", "value": "admin"}]}
   '
   $FABRIC_CA_CLIENTEXEC identity add ${user}2 $URI -d --json "$userdef" -H $TESTDIR/admin2 2>&1 |
      grepPrint "Cannot register fixed value attribute 'hf.EnrollmentID'" ||
         ErrorMsg "Should not be able to configure 'hf.EnrollmentID'"
}

function removeAllUsers() {
   # Objective:
   # Ensure that a valid authorized admin may delete users
   # Ensure that a deleted users' certiifcates ae revoked
   # Ensure correct error when deletiing non-existent user
   # Ensure we may not delete self with the --force flag
   # At each step, verify the expected number of user entries in DB

   # delete everyone except for admin
   for u in $( $FABRIC_CA_CLIENTEXEC identity list $URI -H $TESTDIR/admin/ |
                awk '{for (i=1;i<=NR;i++) {gsub(/,/,"");if ($i=="Name:" && $(i+1)!="admin") print $(i+1) }}'); do
      $FABRIC_CA_CLIENTEXEC identity remove $u $URI -d -H $TESTDIR/admin/ || ErrorMsg "Failed to delete user $u"
   done
   $FABRIC_CA_CLIENTEXEC identity list $u $URI -H $TESTDIR/admin/
   numUsers=$($FABRIC_CA_CLIENTEXEC identity list $u $URI -H $TESTDIR/admin/ | wc -l)
   test "$numUsers" -ne 1 && ErrorMsg "Wrong number of users"

   # ensure all user certs revoked
   $SCRIPTDIR/fabric-ca_setup.sh -L -d mysql -D 2>/dev/null|
      sed -n '/Certificates:/,/Affiliations:/p' | sed '1,2d;$d' |
         awk -v rc=0 '$1!="admin" {if ($4!="revoked") rc++}; END {exit rc}' ||
            ErrorMsg "Not all certs have been revoked"

   # delete non-existent user (should return '404')
   $FABRIC_CA_CLIENTEXEC identity remove id $URI -H $TESTDIR/admin/ 2>&1 |
      grepPrint 'Failed to get User' ||
         ErrorMsg "Should have failed, or wrong error code"
   # attempt delete self w/o force
   $FABRIC_CA_CLIENTEXEC identity remove admin $URI -H $TESTDIR/admin/ 2>&1 |
       grepPrint "Need to use 'force'" ||
          ErrorMsg "Should have failed, or wrong error code"
   # delete self
   $FABRIC_CA_CLIENTEXEC identity remove admin $URI --force -H $TESTDIR/admin/ ||
       ErrorMsg "Failed to delete self"
   numUsers=$(./scripts/fvt/fabric-ca_setup.sh -L -d mysql 2>/dev/null|
               sed -n '/Users/,$p' | sed '1d' | wc -l)
   test "$numUsers" -ne 0 && ErrorMsg "Wrong number of users"
}

export -f register

### Start Test ###
export CA_CFG_PATH=$TESTDIR
$SCRIPTDIR/fabric-ca_setup.sh -D -R -x $TESTDIR
mkdir -p $TESTDIR
$SCRIPTDIR/fabric-ca_setup.sh -d mysql -I -X -n1 -D -x $TESTDIR
cp $TESTDIR/runFabricCaFvt.yaml /tmp
$SCRIPTDIR/fabric-ca_setup.sh -D -R -x $TESTDIR
mkdir -p $TESTDIR
cp /tmp/runFabricCaFvt.yaml  $TESTDIR/runFabricCaFvt.yaml
sed -i '/name: admin$/,/hf.Registrar.DelegateRoles:/s/hf.Registrar.Roles:.*/hf.Registrar.Roles: "client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange,ca\"/;
        s/hf.Registrar.DelegateRoles:.*/hf.Registrar.DelegateRoles: "client,user,peer,validator,auditor,ca,app,role1,role2,role3,role4,role5,role6,role7,role8,apple,orange,ca\"/'  $TESTDIR/runFabricCaFvt.yaml
$SCRIPTDIR/fabric-ca_setup.sh -d mysql -S -X -n1 -D -x $TESTDIR -- \
                 --cfg.identities.allowremove > $TESTDIR/server.log 2>&1

URI="-u ${PROTO}@$CA_HOST_ADDRESS:$PROXY_PORT $TLSOPT"

enroll
printf "\n\n"
echo "===============> testHfAttrs..."
testHfAttrs

printf "\n\n"
echo "===============> testLateralAffiliation..."
testLateralAffiliation

printf "\n\n"
echo "===============> testDelegation..."
testDelegation

printf "\n\n"
echo "===============> testDefaults..."
testDefaults

printf "\n\n"
echo "===============> testAuthenticationAuthorization..."
testAuthenticationAuthorization

printf "\n\n"
echo "===============> testRoleAuthorization..."
testRoleAuthorization
enroll revoker revokerpw
enroll admin2 adminpw2

printf "\n\n"
echo "===============> testModifyRegistrarRoles..."
testModifyRegistrarRoles

printf "\n\n"
echo "===============> testAffiliation..."
testAffiliation

printf "\n\n"
echo "===============> testHfAttrs..."
testHfAttrs

printf "\n\n"
echo "===============> testConflictingHfAttrs..."
testConflictingHfAttrs admin2 conflictedUser

printf "\n\n"
echo "===============> removeAllUsers..."
removeAllUsers


CleanUp $RC
exit $RC