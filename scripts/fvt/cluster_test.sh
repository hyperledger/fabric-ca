#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE="ca_cluster"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
ROOTDIR=/tmp/cluster
INTDIR=$ROOTDIR/int
ROOTUSERDIR=$ROOTDIR/users
INTUSERDIR=$ROOTDIR/int/users
ENROLLCERT=msp/signcerts/cert.pem
DEFAULT_CA_CONFIG=fabric-ca-config.yaml
RC=0
DBNAME=fabric_ca
INTDBNAME=intfabric_ca
NUMSERVER="$1"  # Number of CA instances behind the proxy
NUMINTERMD="$2"  # Number of intermediate CAs
NUMCAS="$3"      # cacount; as a simplifying assumption,
                 #    if NUMSERVER > NUMCAS,
                 #    then NUMSERVER % NUMCAS = 0
                 #    else NUMCAS % NUMSERVER = 0
ITERATIONS="$4"  # num of commands to run in parallel
                 # As a simplifying assumption, ITERATIONS % 4 = 0
NUMJOBS="$5"     # num of concurrent jobs

# Using the default, the test should complete in ≈ 1 min
: ${NUMSERVER:=2}
: ${NUMINTERMD:=2}
: ${NUMCAS:=2}
: ${ITERATIONS:=8}
: ${NUMJOBS:=1024}   # spawn as many jobs as there are potential requests
NUMUSERS=$((NUMCAS*ITERATIONS)) # NUMUSERS % NUMSERVER should = 0
USERNAME="testuser"
ROOT_CA_ADDR=localhost
INTUSER="intermediateCa16"
INTPSWD="intermediateCa16pw"
SHELL=/bin/bash

export SHELL PROXY_PORT ROOTDIR ITERATIONS USERNAME PROTO FABRIC_CA_CLIENTEXEC ENROLLCERT

function enrollAdmin() {
   local port="$1"
   local ca="$2"
   local dir="$3"
   : ${port:=$PROXY_PORT}

   mkdir -p $dir/admin$ca
   touch $dir/admin$ca/log.txt
   FABRIC_CA_CLIENT_HOME=$dir/admin$ca \
   $FABRIC_CA_CLIENTEXEC enroll --debug $TLSOPT \
     -u ${PROTO}admin:adminpw@localhost:$port \
     --csr.hosts admin@fab-client.raleigh.ibm.com \
     --csr.hosts admin.fabric.raleigh.ibm.com,127.0.0.2 \
     --caname ca$ca >> $dir/admin$ca/log.txt 2>&1
}

function revokeUsers() {
   local port="$1"
   local ca="$2"
   local user="$3"
   local dir="$4"
   : ${port:=$PROXY_PORT}

   FABRIC_CA_CLIENT_HOME=$dir/admin$ca \
   $FABRIC_CA_CLIENTEXEC revoke --gencrl --debug $TLSOPT \
     -u ${PROTO}admin:adminpw@localhost:$port \
     --revoke.name ${USERNAME}${ca}-${user} \
     --caname ca$ca >> $dir/admin$ca/log.txt 2>&1
}

function enrollUsers() {
   local port="$1"
   local ca="$2"
   local user="$3"
   local dir="$4"
   : ${port:=$PROXY_PORT}
   mkdir -p $dir/admin$ca
   touch $dir/admin$ca/log.txt
   FABRIC_CA_CLIENT_HOME=$dir/${USERNAME}${ca}-${user} \
   $FABRIC_CA_CLIENTEXEC enroll --debug $TLSOPT \
     -u ${PROTO}${USERNAME}${ca}-${user}:${USERNAME}${ca}-${user}@localhost:$port \
     --csr.hosts ${USERNAME}${ca}-${user}@fab-client.raleigh.ibm.com \
     --csr.hosts ${USERNAME}${ca}-${user}.fabric.raleigh.ibm.com \
     --caname ca$ca >> $dir/admin$ca/log.txt 2>&1
   test "${USERNAME}${ca}-${user}" = "$(openssl x509 -in $dir/${USERNAME}${ca}-${user}/$ENROLLCERT -noout -subject | awk -F'= ' '{print $NF}')"
}

function reenrollUsers() {
   local port="$1"
   local ca="$2"
   local user="$3"
   local dir="$4"
   : ${port:=$PROXY_PORT}
   mkdir -p $dir/admin$ca
   touch $dir/admin$ca/log.txt
   FABRIC_CA_CLIENT_HOME=$dir/${USERNAME}${ca}-${user} \
   $FABRIC_CA_CLIENTEXEC reenroll --debug $TLSOPT \
     -u ${PROTO}@localhost:$port \
     --caname ca$ca >> $dir/admin$ca/log.txt 2>&1
   test "${USERNAME}${ca}-${user}" = "$(openssl x509 -in $dir/${USERNAME}${ca}-${user}/$ENROLLCERT -noout -subject | awk -F'= ' '{print $NF}')"
}

function register() {
   local port="$1"
   local ca="$2"
   local user="$3"
   local dir="$4"
   : ${port:=$PROXY_PORT}
   FABRIC_CA_CLIENT_HOME=$dir/admin$ca \
   $FABRIC_CA_CLIENTEXEC register --debug -u ${PROTO}localhost:$port $TLSOPT \
   --id.name ${USERNAME}${ca}-${user} \
   --id.secret ${USERNAME}${ca}-${user} \
   --id.type client \
   --id.maxenrollments $ITERATIONS \
   --id.affiliation bank_a \
   --id.attrs test=testValue \
   --caname ca$ca >> $dir/admin$ca/log.txt 2>&1
}

function DBvalidateUsers() {
   # Query the DB and verify the user state:
   #  0 - registered, but not enrolled
   #  1 - enrolled
   local state="$1"
   local dbname="$2"
   local StatusField=6
   local fsopt=""

   case $DRIVER in
      postgres) StatusField=11 ;;
   esac

   DBNAME=$dbname $SCRIPTDIR/fabric-ca_setup.sh -L -d $DRIVER \
        -n $NUMSERVER -u $NUMCAS 2>/dev/null |
   awk -v u="$USERNAME" $fsopt \
       -v s="$state" \
       -v n="$NUMUSERS" \
       -v f="$StatusField" \
       -v t=0 '
      $1~u && $f==s {t++}
      END { if (t!=n) exit 1 }'
}

function showUsers() {
   $SCRIPTDIR/fabric-ca_setup.sh -L -d $DRIVER  \
        -n $NUMSERVER -u $NUMCAS 2>/dev/null |
   awk -v u="$USERNAME" '$1~u'
}

export -f enrollAdmin register enrollUsers revokeUsers reenrollUsers

function checkStatus() {
   # Parse the joblog exitstatus (column 7) for all jobs
   #  0  - success
   #  ^0 - failed
   # Success is measured by the number of successful jobs, i.e.,
   # there should be one successful job for each request sent:
   #   Number of exit '0' entries == NUMUSERS
   local log="$1"
   local number="$2"
   : ${number:="$NUMUSERS"}
   awk -v u=$number '
         NR!=1 && $7==0 {rc+=1}
         END {if (rc!=u) exit 1}' $log
   test $? -ne 0 && ErrorMsg "FAILED" || echo "PASSED"
}


for DRIVER in mysql postgres; do
   echo "Testing $DRIVER >>>>>>>>>>>>>"
   # Delete all of the DBs
   echo -e "   >>>>>>>>>>  Deleting all databases"
   $SCRIPTDIR/fabric-ca_setup.sh -x $ROOTDIR -R -u $NUMCAS
   DBNAME=$INTDBNAME $SCRIPTDIR/fabric-ca_setup.sh -x $ROOTDIR -R -u $NUMCAS
   rm -rf $ROOTDIR

   # Initialize all of the configs, certs, keys and directories
   mkdir -p $ROOTUSERDIR
   mkdir -p $INTUSERDIR
   echo -e "   >>>>>>>>>>  Initializing Root CAs"
   $SCRIPTDIR/fabric-ca_setup.sh -x $ROOTDIR -I -n 1 -u $NUMCAS \
                                 -n $NUMSERVER -D -d $DRIVER > $ROOTDIR/log.txt 2>&1

   echo -e "   >>>>>>>>>>  Initializing Intermediate CAs"

   # Copy root CA config file to int CA home and change the database name
   cp "$ROOTDIR/$DEFAULT_RUN_CONFIG_FILE_NAME" "$INTDIR/$DEFAULT_RUN_CONFIG_FILE_NAME"
   sed -i "/datasource:/ s/datasource:\(.*\)fabric_ca\(.*\)/datasource:\1intfabric_ca\2/" "$INTDIR/$DEFAULT_RUN_CONFIG_FILE_NAME"

   ##################################################################
   ## Customize enrollment for each CA
   ##################################################################
   ca=0
   rootCafiles=""
   intermediateCafiles=""
   rootDBconfig=""
   intermediateDBconfig=""
   # append the customized DB config to each CA's config file
   while test $((ca++)) -lt $NUMCAS; do
      # Copy CA config files of root CA server to int CA home and change the database name
      mkdir -p "$INTDIR/ca/ca$ca" || true
      cp "$ROOTDIR/ca/ca$ca/fabric-ca-config.yaml" "$INTDIR/ca/ca$ca/fabric-ca-config.yaml"
      sed -i "/datasource:/ s/datasource:\(.*\)fabric_ca_ca$ca\(.*\)/datasource:\1intfabric_ca_ca$ca\2/" "$INTDIR/ca/ca$ca/fabric-ca-config.yaml"

      # build the list of cafiles to be passed to server start
      rootCafiles="$rootCafiles,$ROOTDIR/ca/ca$ca/${DEFAULT_CA_CONFIG}"
      intermediateCafiles="$intermediateCafiles,$INTDIR/ca/ca$ca/${DEFAULT_CA_CONFIG}"

      # each intermediate CA needs an enrollment identity and parentserver.url
      # each also needs a unique caname, or the sever start will fail
      enrollment="
intermediate:
  parentserver:
    url: ${PROTO}intermediateCa${ca}:intermediateCa${ca}pw@127.0.0.1:$CA_DEFAULT_PORT
    caname: ca${ca}
  enrollment:
    name: intermediateCa${ca}
    secret: intermediateCa${ca}pw
    hosts:
       - localhost
"
      # append the intermediate CA config to each CA's config
      cat >> $INTDIR/ca/ca$ca/${DEFAULT_CA_CONFIG} <<EOF
$enrollment
EOF
   done

   # strip the leading comma from the files list
   rootCafiles=${rootCafiles#,}
   intermediateCafiles=${intermediateCafiles#,}
   # remove the pathlength restriction
   sed -i 's/cacount:.*/cacount:/g
           s/maxpathlen:.*/maxpathlen:/g
           s/pathlength:.*/pathlength:/g' $ROOTDIR/runFabricCaFvt.yaml $INTDIR/runFabricCaFvt.yaml
   # Remove all of the CSR.CN data from intermediate CAs --
   # otherwise, server startup will fail
   find $INTDIR/ca -name $DEFAULT_CA_CONFIG -exec sed -i "s/cn:.*/cn:/g" {} \;

   # Start all Root and intermediate CAs
   echo -e "   >>>>>>>>>>  Starting $NUMSERVER Root CA instances with $NUMCAS servers each"
   $SCRIPTDIR/fabric-ca_setup.sh -N -X -x $ROOTDIR -S -n $NUMSERVER -D -d $DRIVER \
                                 -- "--cafiles" "$rootCafiles" >> $ROOTDIR/log.txt 2>&1 ||
                                 ErrorExit "Failed to start root servers"
   echo -e "   >>>>>>>>>>  Starting $NUMSERVER Intermediate CA instances with $NUMCAS servers each"

   $SCRIPTDIR/fabric-ca_setup.sh -n $NUMSERVER -S -r $INTERMEDIATE_CA_DEFAULT_PORT -x $INTDIR \
                                 -U "https://$INTUSER:$INTPSWD@$ROOT_CA_ADDR:$PROXY_PORT" \
                                 --  "--cafiles" "$intermediateCafiles" >> $INTDIR/log.txt 2>&1 ||
                                 ErrorExit "Failed to start intermediate servers"

   #########################################################
   # The bulk of the work comes here  --
   # register and enroll users, in parallel, $NUMJOBS at a time
   #########################################################
   for SERVER in $PROXY_PORT $INTERMEDIATE_PROXY_PORT ; do
      # The intermediate CAs do not share the root CA's DBs;
      # each has a unique DB (in a unique directory, if file-based
      # If the CA is root, the haproxy backend name is 'server'
      # If the CA is intermediate, the haproxy backend name is 'intserver'
      if test "$SERVER" = "$INTERMEDIATE_PROXY_PORT"; then
         dbname=$INTDBNAME
         userdir=$INTUSERDIR
         stype=intermediate
         backend=intserver
      else
         dbname=$DBNAME
         userdir=$ROOTUSERDIR
         stype=root
         backend=server
      fi

      count=0

      echo -e "      >>>>>>>>>>  Testing $stype CA using DB name $dbname"

      # Enroll the admins -- the total number of enrollment requests
      # sent is calulated to be the larger of NUMSERVER | NUMCAS
      test $NUMCAS -ge $NUMSERVER && numReq=1 || numReq=$((NUMSERVER/NUMCAS))
      printf "         >>>>>>>>>>  Enrolling ${NUMCAS} admins, $numReq times..."
      parallel -k --no-notice --jobs $NUMJOBS --joblog $userdir/adminEnroll.log \
         enrollAdmin $SERVER {1} $userdir ::: $(seq $NUMCAS) ::: $(seq $numReq)
      checkStatus $userdir/adminEnroll.log $((numReq*NUMCAS)) || ErrorExit "Enroll of admins failed"
      # Register $NUMUSERS users and validate their status in the DB
      test $NUMCAS -lt $NUMSERVER && count=1 || count=$((NUMCAS/NUMSERVER))

      # Register $NUMUSERS users and validate their status in the DB
      printf "         >>>>>>>>>>  Registering $NUMUSERS users (${NUMCAS}x${ITERATIONS})..."
      parallel --no-notice --jobs $NUMJOBS --joblog $userdir/register.log \
         register $SERVER {1} {2} $userdir ::: $(seq $NUMCAS) ::: $(seq $ITERATIONS)
      checkStatus $userdir/register.log
      DBvalidateUsers 0 $dbname &&
          echo -e "         >>>>>>>>>>  Validating user status in DB...PASSED" ||
          ErrorMsg "         >>>>>>>>>>  Validating user status in DB...FAILED"
      count=$((count+$((ITERATIONS*NUMCAS/NUMSERVER)) ))

      # Enroll $NUMUSERS users and validate their status in the DB
      printf "         >>>>>>>>>>  Enrolling $NUMUSERS users (${NUMCAS}x${ITERATIONS})..."
      parallel --no-notice --jobs $NUMJOBS --joblog $userdir/userEnroll.log \
         enrollUsers $SERVER {1} {2} $userdir ::: $(seq $NUMCAS) ::: $(seq $ITERATIONS)
      checkStatus $userdir/userEnroll.log
      DBvalidateUsers 1 $dbname &&
          echo -e "         >>>>>>>>>>  Validating user status in DB...PASSED" ||
          ErrorMsg "         >>>>>>>>>>  Validating user status in DB...FAILED"
      count=$((count+$((ITERATIONS*NUMCAS/NUMSERVER)) ))

      # Do all of the following simultaneously
      #  enroll      Enroll an identity
      #  getcacert   Get CA certificate chain
      #  reenroll    Reenroll an identity
      #  register    Register an identity
      #  revoke      Revoke an identity
      #  gencrl      Generate a CRL

      > /tmp/cmd.lst
      for ca in $(seq $NUMCAS); do
         # Create the register cmd list of brand new users where
         #     the previous register task left off
         echo "               >>>>>>>  generating register command list ($((ITERATIONS*NUMCAS)))"
         for user in $(seq $((ITERATIONS+1)) $((ITERATIONS+ITERATIONS)) ); do
           echo register $SERVER $ca $user $userdir >> /tmp/cmd.lst
         done
         # Create the enroll cmd list -
         #     issue enroll for the first 1/2 of the previously enrolled users
         echo "               >>>>>>>  generating enroll command list ($((ITERATIONS/2*NUMCAS)))"
         for user in $(seq $((ITERATIONS/2)) ); do
            echo enrollUsers $SERVER $ca $user $userdir >> /tmp/cmd.lst
         done
         # Create the renroll cmd list -
         #     issue renroll for the third 1/4 of the previously enrolled users
         echo "               >>>>>>>  generating renroll command list ($((ITERATIONS/4*NUMCAS)))"
         for user in  $(seq $((ITERATIONS/2+1)) $((ITERATIONS/4*3)) ); do
            echo reenrollUsers $SERVER $ca $user $userdir >> /tmp/cmd.lst
         done
         # Create the revoke cmd list -
         #     issue renroll for the last 1/4 of the previously enrolled users
         echo "               >>>>>>>  generating revoke command list ($((ITERATIONS/4*NUMCAS)))"
         for user in  $(seq $((ITERATIONS/4*3+1)) $ITERATIONS ); do
            echo revokeUsers $SERVER $ca $user $userdir >> /tmp/cmd.lst
         done
         # Create the getcacert cmd list -
         echo "               >>>>>>>  generating getcacert command list ($((ITERATIONS*NUMCAS/2)))"
         for user in $(seq $((ITERATIONS/2)) ); do
            echo "FABRIC_CA_CLIENT_HOME=$userdir/admin$ca $FABRIC_CA_CLIENTEXEC getcacert --debug -u ${PROTO}localhost:$SERVER $TLSOPT --caname ca$ca > $userdir/admin$ca/cacert.txt 2>&1" >> /tmp/cmd.lst
         done
         # Create the gencrl cmd list -
         echo "               >>>>>>>  generating gencrl command list ($((ITERATIONS*NUMCAS/2)))"
         for user in $(seq $((ITERATIONS/2+1)) $ITERATIONS); do
            echo "FABRIC_CA_CLIENT_HOME=$userdir/admin$ca $FABRIC_CA_CLIENTEXEC gencrl --debug -u ${PROTO}localhost:$SERVER $TLSOPT --caname ca$ca > $userdir/admin$ca/crl.txt 2>&1" >> /tmp/cmd.lst
         done
      done

      shuf --output=$userdir/cmd.lst /tmp/cmd.lst
      # OK, here goes...
      printf "         >>>>>>>>>>  Executing all $((ITERATIONS*3*NUMCAS)) jobs..."
      parallel --no-notice --jobs $NUMJOBS --joblog $userdir/cmd.log < $userdir/cmd.lst
      checkStatus $userdir/cmd.log $((ITERATIONS*3*NUMCAS))
      count=$((count+$((ITERATIONS*3*NUMCAS/NUMSERVER))))

      sleep 1
      # Lastly, 1/4 of user certs should be revoked
      echo "         >>>>>>>>>>  Checking crl; expect $((ITERATIONS/4)) revoked certificates..."
      for ca in $(seq $NUMCAS); do
         FABRIC_CA_CLIENT_HOME=$userdir/admin$ca $FABRIC_CA_CLIENTEXEC gencrl --debug -u ${PROTO}localhost:$SERVER $TLSOPT --caname ca$ca > $userdir/admin$ca/crl.txt 2>&1
         revoked=$(openssl crl -in  $userdir/admin$ca/msp/crls/crl.pem -text -noout | grep -c 'Serial Number:')
         test $revoked -eq $((ITERATIONS/4)) &&
            echo -e "            >>>>>>>>>>  crl check for ca$ca ...PASSED" ||
            ErrorMsg "            >>>>>>>>>>  crl check for ca$ca...FAILED got ('$revoked') revoked certs on localhost:$SERVER"
      done

      # issue revoke for the third 1/4 of the previously enrolled users;
      # count the number of entries in the base crl
      for ca in $(seq $NUMCAS); do
         #prev_revoked=$(openssl crl -noout -text -in $userdir/admin$ca/msp/crls/crl.pem | grep -c 'Serial Number:')
         ### @TODO Work-around for FAB-7223: CRL pem file should wrap at 64 characters ###
         prev_revoked="$(fold -w 64 $userdir/admin$ca/msp/crls/crl.pem | openssl crl -noout -text | grep -c 'Serial Number:')"
         for user in  $(seq $((ITERATIONS/2+1)) $((ITERATIONS/4*3)) ); do
            # delete the current crl
            rm $userdir/admin$ca/msp/crls/crl.pem
            revokeUsers $SERVER $ca $user $userdir
            # 2 entries should be added to the base crl for each revocation
            # since this group of users has re-enrolled (have two e-certs)
            #curr_revoked=$(openssl crl -noout -text -in $userdir/admin$ca/msp/crls/crl.pem | grep -c 'Serial Number:')
            curr_revoked="$(fold -w 64 $userdir/admin$ca/msp/crls/crl.pem | openssl crl -noout -text | grep -c 'Serial Number:')"
            test "$((curr_revoked-prev_revoked))" -eq 2  &&
               echo -e "            >>>>>>>>>>  revoke/gencrl check for ${stype}CA${ca}...PASSED" ||
               ErrorMsg "            >>>>>>>>>>  wrong number of certs in CRL for ${stype}CA${ca}...FAILED got ('$curr_revoked') revoked certs on localhost:$SERVER"
            prev_revoked=$curr_revoked
         done
      done
   done
   echo ""
   echo ""
done

# Delete all of the DBs
echo -e "   >>>>>>>>>>  Deleting all databases"
$SCRIPTDIR/fabric-ca_setup.sh -x $ROOTDIR -R -u $NUMCAS
DBNAME=$INTDBNAME $SCRIPTDIR/fabric-ca_setup.sh -x $ROOTDIR -R -u $NUMCAS
CleanUp $RC
exit $RC
