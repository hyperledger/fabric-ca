#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

dbDriver=postgres

: ${TESTCASE="aff_modify"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
TESTDIR=/tmp/$TESTCASE
RC=0
NUMROLES=8

# defaults
declare -A defaultValues
defaultValues=([Maxenrollments]=2147483647 [Affiliation]='.' [Type]="user" [Passwd]="user1pw")

function tableCount() {
   driver="$1"
   tableType="$2"
   shift 2
   $SCRIPTDIR/fabric-ca_setup.sh -L -d $driver -D | sed -n "/$tableType:/,/^.*: *$/p" | sed '1,3d;$d' |
      awk -v s="$*" '
         BEGIN { n=split(s, terms) }
         {
            for (i in terms)
               if (match(tolower($0), tolower(terms[i]))) val[terms[i]]++
         }
         END { for (i in terms) {
                  printf terms[i]":"
                  print val[terms[i]] ? val[terms[i]] : "0"
               }
         }'
}

function displayRunningTotal() {
   tableCount $dbDriver Affiliations "planet0 planet1 planet2 planetx"
}

function verifyTotals() {
   totals="$(displayRunningTotal | sort | awk -F':' '{printf $2" "}')"
   expected="$(echo $@ | sed 's/ \+/ /')"
   test "${totals%% }" = "${expected:-"0"}" || return 1
}

function genAffYaml() {
   export FABRIC_CA_CLIENT_HOME=$TESTDIR/admin
   local Planet=(0 1 2)
   local Landmass=(0 1)
   local Country=(0 1)
   local Province=(0 1 2)
   local Locale=(0 1)
   local City=(0 1 2)
   local Hood=(0 1 2 3)
   echo "affiliations:"
   indent="${indent}  "
   echo "${indent}org1:"
   echo "${indent}  - department1"
   echo "${indent}  - department2"
   for P in ${Planet[@]}; do
     echo "${indent}Planet$P:"
     indent="${indent}  "
     for L in ${Landmass[@]}; do
       echo "${indent}Landmass$L:"
       indent="${indent}  "
        for C in ${Country[@]}; do
         echo "${indent}Country$C:"
         indent="${indent}  "
         for R in ${Province[@]}; do
            echo "${indent}Province$R:"
            indent="${indent}  "
           for O in ${Locale[@]}; do
             echo "${indent}Locale$O:"
             indent="${indent}  "
             for I in ${City[@]}; do
               echo "${indent}City$I:"
               indent="${indent}  "
               for H in ${Hood[@]}; do
                 echo "${indent}- Hood$H"
               done
               indent="${indent#  }"
             done
             indent="${indent#  }"
           done
           indent="${indent#  }"
         done
         indent="${indent#  }"
       done
       indent="${indent#  }"
     done
     indent="${indent#  }"
   done
   echo "${indent}org2:"
   echo "${indent}  - department1"
   echo "${indent}  - department2"
}

function setupServerEnv() {
   $SCRIPTDIR/fabric-ca_setup.sh -d $dbDriver -I -S -X -n1 -D -x $TESTDIR > $TESTDIR/server.log 2>&1
   enroll
   # Ensure affiliations cannot be deleted if --cfg.affiliations.allowremove not configured
   $FABRIC_CA_CLIENTEXEC affiliation remove org1 $URI -H $TESTDIR/admin/ 2>&1|
      grep 'Authorization failure' ||
         ErrorMsg "should not be able to delete 'org1', or wrong error msg"
   $SCRIPTDIR/fabric-ca_setup.sh -K

   # Generate a large affinity tree for testing;
   # this is way faster than adding with the cmd-line client
   genAffYaml >> $CA_CFG_PATH/runFabricCaFvt.yaml
   $SCRIPTDIR/fabric-ca_setup.sh -d $dbDriver -S -X -n1 -D -x $TESTDIR -- \
                    --cfg.affiliations.allowremove > $TESTDIR/server.log 2>&1
   # Sanity check the number of affilitations
   dbEntries=$(tableCount $dbDriver Affiliations ".*"| awk -F':' '{print $2}')
   # discount the summary line displayed in the above command
   let dbEntries--
   serverEntries="$(( $($FABRIC_CA_CLIENTEXEC affiliation list $URI -H $TESTDIR/admin/ | wc -l)  -1))"
   test "$dbEntries" -eq "$serverEntries" || ErrorMsg "Wrong number of affiliations: expected $dbEntries, got $serverEntries"
   displayRunningTotal
   verifyTotals "403 403 403 0" || ErrorMsg "Wrong number of affiliations"
}

function testAffiliationRefs() {
   # @TODO all of these should be 400 bad request FAB-7466
   # Ensure affiliations w/ sub-affiliations cannot be deleted w/o --force
   $FABRIC_CA_CLIENTEXEC affiliation remove org1 $URI -H $TESTDIR/admin/ -d 2>&1 |
      grep "Authorization failure" ||
         ErrorMsg "should not be able to delete 'org1' w/o force (has sub-affiliations)"
   # Ensure affiliations can be deleted if no ID's are referencing them
   $FABRIC_CA_CLIENTEXEC affiliation remove org1.department1 $URI -H $TESTDIR/admin/ -d 2>&1 ||
         ErrorMsg "should be able to delete org1.department1"
   $FABRIC_CA_CLIENTEXEC affiliation remove org1 --force $URI -H $TESTDIR/admin/ -d 2>&1 ||
         ErrorMsg "should be able to delete org1"
   # Ensure affiliations can be deleted, even if ID's are referencing them, but only w/ --force
   $FABRIC_CA_CLIENTEXEC affiliation remove bank_b $URI -H $TESTDIR/admin/ -d 2>&1 &&
      ErrorMsg "should not be able to delete 'bank_b' with references"
   # Ensure affiliations cannot be deleted if ID's are referencing them,
   # and --cfg.identities.allowremove is not configed, even w/ --force
   $FABRIC_CA_CLIENTEXEC affiliation remove bank_b $URI -H $TESTDIR/admin/ --force -d 2>&1 &&
      ErrorMsg "should be able to delete 'bank_b' without --cfg.identities.allowremove"
}

function testAllowremove() {
   # ensure cfg.identities.allowremove flag is required
   $FABRIC_CA_CLIENTEXEC affiliation remove bank_b --force $URI -H $TESTDIR/admin/ 2>&1 |
      grep 'Authorization failure' ||
         ErrorMsg "should not be able to delete 'bank_b', or wrong error msg"
   # add cfg.identities.allowremove flag
   $SCRIPTDIR/fabric-ca_setup.sh -K
   $SCRIPTDIR/fabric-ca_setup.sh -d $dbDriver -S -X -n1 -D -x $TESTDIR -- \
                    --cfg.affiliations.allowremove --cfg.identities.allowremove > $TESTDIR/server.log 2>&1
   # try again
   $FABRIC_CA_CLIENTEXEC affiliation remove bank_b --force $URI -H $TESTDIR/admin/ 2>&1  || ErrorMsg "should be able to delete 'bank_b'"
   # make sure entries are deleted
   $SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver -D | grep bank_b && ErrorMsg "'bank_b' not deleted"
   expected=$((dbEntries - 2))
   dbEntries=$(tableCount $dbDriver Affiliations ".*"| awk -F':' '{print $2}')
   let dbEntries--
   serverEntries="$(( $($FABRIC_CA_CLIENTEXEC affiliation list $URI -H $TESTDIR/admin/ | wc -l)  -1))"
   test "$expected" -eq "$serverEntries" || ErrorMsg "Wrong number of affiliations: expected $expected, got $serverEntries"
   displayRunningTotal
   verifyTotals "403 403 403 0" || ErrorMsg "Wrong number of affiliations"

   # Ensure all children are deleted
   $FABRIC_CA_CLIENTEXEC affiliation remove planet2.landmass1 --force $URI -H $TESTDIR/admin/ 2>&1 ||
      ErrorMsg "should be able to delete 'planet2.landmass1'"
   # make sure entries are deleted
   $SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver -D | grep "planet2.landmass1" && ErrorMsg "'planet2.landmass1' not deleted"
   expected=$((dbEntries - 201))
   dbEntries=$(tableCount $dbDriver Affiliations ".*"| awk -F':' '{print $2}')
   let dbEntries--
   serverEntries="$(( $($FABRIC_CA_CLIENTEXEC affiliation list $URI -H $TESTDIR/admin/ | wc -l)  -1))"
   test "$expected" -eq "$serverEntries" || ErrorMsg "Wrong number of affiliations: expected $expected, got $serverEntries"
   displayRunningTotal
   verifyTotals "403 403 202 0" || ErrorMsg "Wrong number of affiliations"
}

function testAffiliationMgr() {
   # Ensure affiliations can only be updated by authorized users
   enroll admin2 adminpw2
   $FABRIC_CA_CLIENTEXEC affiliation remove org2 $URI -H $TESTDIR/admin2 2>&1 |
      grep "User does not have attribute 'hf.AffiliationMgr'" ||
         ErrorMsg  "Should not be able to delete attributes, or wrong error msg"

   # Ensure admin cannot add affiliations higher in it's affiliation tree
   $FABRIC_CA_CLIENTEXEC identity add affman $URI -H $TESTDIR/admin --secret passwd \
          --attrs '"hf.Registrar.Roles=client,user,peer,validator,auditor,ca"' \
          --affiliation "planet2.landmass0.country1.province0"
   $FABRIC_CA_CLIENTEXEC identity modify affman --attrs "hf.AffiliationMgr=1" $URI -H $TESTDIR/admin
   enroll affman passwd
}

function testTreePruningFailCases() {
   # higher
   $FABRIC_CA_CLIENTEXEC affiliation remove planet2.landmass0.country1 $URI -H $TESTDIR/affman/ -d 2>&1 |
      grep 'Authorization failure' || ErrorMsg "Should not be able to delete 'planet2.landmass0.country1"
   $FABRIC_CA_CLIENTEXEC affiliation add planet2.landmass0.country10 $URI -H $TESTDIR/affman/ -d 2>&1 |
      grep 'Authorization failure' || ErrorMsg "Should not be able to add 'planet2.landmass0.country10"
   # lateral
   $FABRIC_CA_CLIENTEXEC affiliation remove planet2.landmass0.country1.province1 $URI -H $TESTDIR/affman/ -d 2>&1 |
      grep 'Authorization failure' || ErrorMsg "Should not be able to delete 'planet2.landmass0.country1.province1"
   $FABRIC_CA_CLIENTEXEC affiliation add planet2.landmass0.country1.province10 $URI -H $TESTDIR/affman/ -d 2>&1 |
      grep 'Authorization failure' || ErrorMsg "Should not be able to delete 'planet2.landmass0.country1.province10"
   # cannot delete own affiliation
   $FABRIC_CA_CLIENTEXEC affiliation remove planet2.landmass0.country1.province0 $URI -H $TESTDIR/affman/ -d 2>&1 |
      grep 'Authorization failure' || ErrorMsg "Should not be able to delete own affiliation"
   for l in 0 1; do for c in 0 1 2; do for h in 0 1 2 3; do
      $FABRIC_CA_CLIENTEXEC identity add newuser$l$c$h $URI -H $TESTDIR/admin --secret passwd \
          --affiliation "planet2.landmass0.country1.province0.locale$l.city$c.Hood$h"
      enroll newuser$l$c$h passwd > /dev/null
   done; done; done

   # --force needed when users are impacted
   $FABRIC_CA_CLIENTEXEC affiliation modify planet2 --name planetX $URI -H $TESTDIR/admin 2>&1 |
      grep "Need to use 'force'" || ErrorMsg "Should not be able to modify affiliation w/o --force"
   $FABRIC_CA_CLIENTEXEC affiliation modify planet2 --name planetX --force $URI -H $TESTDIR/admin ||
         ErrorMsg "Should be able to modify affiliation w/ --force"
   displayRunningTotal
   verifyTotals "403 403 0 202" || ErrorMsg "Wrong number of affiliations"
   test $($SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver | grep planetX | wc -l) -eq 25 ||
      ErrorMsg "Wrong number of users"
}

function testTreePruningSuccessCases() {
   # lower, succeeds -- all children deleted
   $FABRIC_CA_CLIENTEXEC affiliation remove --force planetX.landmass0.country1.province0.locale0 $URI -H $TESTDIR/affman ||
      ErrorMsg "Should be able to delete lower affiliation"
   displayRunningTotal
   verifyTotals "403 403 0 186" || ErrorMsg "Wrong number of affiliations"
   test $($SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver | grep planetX | wc -l) -eq 13 ||
      ErrorMsg "Wrong number of users"
   $FABRIC_CA_CLIENTEXEC affiliation add planetX.landmass0.country1.province0.locale10 $URI -H $TESTDIR/affman ||
      ErrorMsg "Should be able to add lower affiliation"
   displayRunningTotal
   verifyTotals "403 403 0 187" || ErrorMsg "Wrong number of affiliations"
   test $($SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver | grep planetX | wc -l) -eq 13 ||
      ErrorMsg "Wrong number of users"
   test $($SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver | grep planetX | wc -l) -eq 13 ||
      ErrorMsg "Wrong number of users"
   $FABRIC_CA_CLIENTEXEC affiliation modify planetX.landmass0.country1.province0.locale10 \
      --name planetX.landmass0.country1.province0.locale11 $URI -H $TESTDIR/affman ||
         ErrorMsg "Should be able to modify lower affiliation"
   displayRunningTotal
   verifyTotals "403 403 0 187" || ErrorMsg "Wrong number of affiliations"
   test $($SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver | grep planetX | wc -l) -eq 13 ||
      ErrorMsg "Wrong number of users"
   # Ensure we accept alternate values
   $FABRIC_CA_CLIENTEXEC identity modify affman --attrs "hf.AffiliationMgr=T" $URI -H $TESTDIR/admin || ErrorMsg "Failed to update affman"
   $FABRIC_CA_CLIENTEXEC affiliation remove --force planetX.landmass0.country1.province0.locale1 $URI -H $TESTDIR/affman/ ||
      ErrorMsg "Should be able to delete lower affiliation"
   displayRunningTotal
   verifyTotals "403 403 0 171" || ErrorMsg "Wrong number of affiliations"
   test $($SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver | grep planetX | wc -l) -eq 1 ||
      ErrorMsg "Wrong number of users"
   # ensure all children are gone
   expected=$((dbEntries - 31))
   dbEntries=$(tableCount $dbDriver Affiliations ".*"| awk -F':' '{print $2}')
   let dbEntries--
   serverEntries="$(( $($FABRIC_CA_CLIENTEXEC affiliation list $URI -H $TESTDIR/admin/ | wc -l)  -1))"
   test "$expected" -eq "$serverEntries" || ErrorMsg "Wrong number of affiliations: expected $expected, got $serverEntries"
   displayRunningTotal
   verifyTotals "403 403 0 171" || ErrorMsg "Wrong number of affiliations"
}

function testCertRevocation() {
   # Ensure any users who are deleted as part of an
   # affiliation deletion have certs revoked;
   # NOTE: $dbDriver stores the status as a binary asci blob,
   # hence the check for '7265766f6b6564' (revoked)
   $SCRIPTDIR/fabric-ca_setup.sh -L -d $dbDriver -D |
      awk -F'|' -v revoked=0 '
         /Certificates:/,/Affiliations:/ {
            if ($1~/newuser/) {
               found+=1
               if ($5!~/7265766f6b6564/) revoked++}}
         END {if (!(found) || revoked>0 ) exit 1}'
   test $? -ne 0 && ErrorMsg "user certs should be revoked"
}

function testAlternateTruthValues() {
   for v in 0 F false; do
      $FABRIC_CA_CLIENTEXEC identity modify affman --attrs "hf.AffiliationMgr=$v" $URI -H $TESTDIR/admin
      $FABRIC_CA_CLIENTEXEC affiliation add planetX.landmass0.country1.province0.locale1.village $URI -H $TESTDIR/affman 2>&1 |
         grep "Authorization failure" || ErrorMsg "Should have failed Authorization"
      $FABRIC_CA_CLIENTEXEC affiliation remove --force planetX.landmass0.country1.province0.locale1 $URI -H $TESTDIR/affman 2>&1 |
         grep "Authorization failure" || ErrorMsg "Should have failed Authorization"
      $FABRIC_CA_CLIENTEXEC affiliation modify planetX.landmass0.country1.province0.locale1 \
         --name planet3 --force $URI -H $TESTDIR/affman 2>&1 |
         grep "Authorization failure" || ErrorMsg "Should have failed Authorization"
   done
}

function testNonExistant() {
   # Attempt to add an affiliation that already exists
   $FABRIC_CA_CLIENTEXEC affiliation add org1 $URI -H $TESTDIR/admin/ -d 2>&1 |
      grep 'Affiliation already exists' ||
         ErrorMsg "should not be able to add 'org1'"
   # Attempt to modify an affiliation that doesn't exist
   $FABRIC_CA_CLIENTEXEC affiliation modify plan9 --name castleBravo $URI -H $TESTDIR/admin/ -d 2>&1 |
      grep '404 Not Found' ||
         ErrorMsg "should not be able to add 'plan9'"
   # Attempt to list an affiliation that doesn't exist
   $FABRIC_CA_CLIENTEXEC affiliation list --affiliation plan9 $URI -H $TESTDIR/admin/ -d 2>&1 |
      grep 'Failed to get affiliation' ||
         ErrorMsg "should not be able to add 'plan9'"
}

export -f register

### Start Test ###
export CA_CFG_PATH=$TESTDIR
$SCRIPTDIR/fabric-ca_setup.sh -D -R -x $TESTDIR
mkdir -p $TESTDIR
URI="-u ${PROTO}@$CA_HOST_ADDRESS:$PROXY_PORT $TLSOPT"

echo -e "\n\n\n =============> Setting up Server"
setupServerEnv
echo -e "\n\n\n =============> testAffiliationRefs"
testAffiliationRefs
echo -e "\n\n\n =============> testAllowremove"
testAllowremove
echo -e "\n\n\n =============> testAffiliationMgr"
testAffiliationMgr
echo -e "\n\n\n =============> testTreePruningFailCases"
testTreePruningFailCases
echo -e "\n\n\n =============> testTreePruningSuccessCases"
testTreePruningSuccessCases
echo -e "\n\n\n =============> testCertRevocation"
testCertRevocation
echo -e "\n\n\n =============> testAlternateTruthValues"
testAlternateTruthValues
echo -e "\n\n\n =============> testNonExistant"
testNonExistant

$SCRIPTDIR/fabric-ca_setup.sh -D -R -x $TESTDIR
CleanUp $RC
exit $RC
