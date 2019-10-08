#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE:="intermediateca-test"}
TDIR=/tmp/$TESTCASE
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
ROOT_CA_ADDR=localhost
TLSDIR="$TDIR/tls"
NUMINTCAS=8
MAXENROLL=$((2*NUMINTCAS))
RC=0
TDIR=/tmp/intermediateca-tests
ROOT_CA_ADDR=localhost
CA_PORT=7054
TLSDIR="$TDIR/tls"

function setupTLScerts() {
   oldhome=$HOME
   rm -rf $TLSDIR
   mkdir -p $TLSDIR
   rm -rf /tmp/CAs $TLSDIR/rootTlsCa* $TLSDIR/subTlsCa*
   export HOME=$TLSDIR
   # Root TLS CA
   $SCRIPTDIR/utils/pki -f newca -a rootTlsCa -t ec -l 256 -d sha256 \
                        -n "/C=US/ST=NC/L=RTP/O=IBM/O=Hyperledger/OU=FVT/CN=localhost/" -S "IP:127.0.0.1,DNS:localhost" \
                        -K "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign" \
                        -E "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping" \
                        -e 20370101000000Z -s 20160101000000Z -p rootTlsCa- >/dev/null 2>&1
   # Sub TLS CA
   $SCRIPTDIR/utils/pki -f newsub -b subTlsCa -a rootTlsCa -t ec -l 256 -d sha256 \
                        -n "/C=US/ST=NC/L=RTP/O=IBM/O=Hyperledger/OU=FVT/CN=subTlsCa/" -S "IP:127.0.0.1" \
                        -K "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign" \
                        -E "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping" \
                        -e 20370101000000Z -s 20160101000000Z -p subTlsCa- >/dev/null 2>&1
   # EE TLS certs
   i=0;while test $((i++)) -lt $((NUMINTCAS+1)); do
   rm -rf $TLSDIR/intFabCaTls${i}*
   $SCRIPTDIR/utils/pki -f newcert -a subTlsCa -t ec -l 256 -d sha512 \
                        -n "/C=US/ST=NC/L=RTP/O=IBM/O=Hyperledger/OU=FVT/CN=intFabCaTls${i}/" -S "IP:127.0.${i}.1" \
                        -K "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign" \
                        -E "serverAuth,clientAuth,codeSigning,emailProtection,timeStamping" \
                        -e 20370101000000Z -s 20160101000000Z -p intFabCaTls${i}- >/dev/null 2>&1 <<EOF
y
y
EOF
   done
   cat $TLSDIR/rootTlsCa-cert.pem $TLSDIR/subTlsCa-cert.pem > $TLSDIR/tlsroots.pem
   HOME=$oldhome
}

function createRootCA() {
   # Start RootCA
   tlsopts="--tls.enabled \
            --tls.certfile $TLSDIR/rootTlsCa-cert.pem \
            --tls.keyfile $TLSDIR/rootTlsCa-key.pem"

   mkdir -p "$TDIR/root"
   $SCRIPTDIR/fabric-ca_setup.sh -I -x "$TDIR/root" -d $driver -m $MAXENROLL -a
   FABRIC_CA_SERVER_HOME="$TDIR/root" fabric-ca-server start \
                                      --csr.hosts $ROOT_CA_ADDR --address $ROOT_CA_ADDR \
                                      $tlsopts -c $TDIR/root/runFabricCaFvt.yaml -d 2>&1 |
                                      tee $TDIR/root/server.log &
   pollFabricCa fabric-ca-server $ROOT_CA_ADDR $CA_DEFAULT_PORT
}

function createIntCA() {
# Start intermediate CAs
   i=0;while test $((i++)) -lt $NUMINTCAS; do
      mkdir -p "$TDIR/int${i}"
      cp "$TDIR/intFabricCaFvt.yaml" "$TDIR/int${i}/runFabricCaFvt.yaml"
      tlsopts="--tls.enabled --tls.certfile $TLSDIR/intFabCaTls${i}-cert.pem \
                             --tls.keyfile $TLSDIR/intFabCaTls${i}-key.pem \
                             --intermediate.tls.certfiles $TLSDIR/tlsroots.pem \
                             --intermediate.tls.client.certfile $TLSDIR/intFabCaTls${i}-cert.pem \
                             --intermediate.tls.client.keyfile $TLSDIR/intFabCaTls${i}-key.pem"
      ADDR=127.0.${i}.1
      FABRIC_CA_SERVER_HOME="$TDIR/int${i}" fabric-ca-server start --csr.hosts $ADDR -c $TDIR/int${i}/runFabricCaFvt.yaml \
                                           --address $ADDR $tlsopts -b admin:adminpw \
                                           -u ${PROTO}intermediateCa$i:intermediateCa${i}pw@$ROOT_CA_ADDR:$CA_DEFAULT_PORT -d 2>&1 |
                                           tee $TDIR/int${i}/server.log &
   done
   i=0;while test $((i++)) -lt $NUMINTCAS; do
      ADDR=127.0.${i}.1
      pollFabricCa "" $ADDR $CA_DEFAULT_PORT
   done
}

function createFailingCA {
   last=$((NUMINTCAS+1))
   mkdir -p "$TDIR/int${last}"
   cp "$TDIR/intFabricCaFvt.yaml" "$TDIR/int${last}/runFabricCaFvt.yaml"
   tlsopts="--tls.enabled --tls.certfile $TLSDIR/intFabCaTls${last}-cert.pem \
                          --tls.keyfile $TLSDIR/intFabCaTls${last}-key.pem \
                          --intermediate.tls.certfiles $TLSDIR/tlsroots.pem \
                          --intermediate.tls.client.certfile $TLSDIR/intFabCaTls${last}-cert.pem \
                          --intermediate.tls.client.keyfile $TLSDIR/intFabCaTls${last}-key.pem"
   FABRIC_CA_SERVER_HOME="$TDIR/int${last}" fabric-ca-server init --csr.hosts 127.0.${last}.1 -c "$TDIR/int${last}/runFabricCaFvt.yaml" \
                                           --address 127.0.${last}.1 $tlsopts -b admin:adminpw \
                                           -u ${PROTO}intermediateCa${last}:intermediateCa${last}pw@$ADDR:$CA_DEFAULT_PORT -d 2>&1 | tee $TDIR/int${last}/server.log
   test ${PIPESTATUS[0]} -eq 0 && return 1 || return 0
}

function enrollUser() {
   local rc=0
   i=0;while test $((i++)) -lt $NUMINTCAS; do
      ADDR=127.0.${i}.1
      /usr/local/bin/fabric-ca-client enroll \
                      --id.maxenrollments $MAXENROLL \
                      -u ${PROTO}admin:adminpw@$ADDR:${CA_DEFAULT_PORT} \
                      -c $TDIR/int${i}/admin/enroll.yaml \
                      --tls.certfiles $TLSDIR/tlsroots.pem \
                      --csr.hosts admin@fab-client.raleigh.ibm.com \
                      --csr.hosts admin.fabric.raleigh.ibm.com,127.42.42.$i
      rc=$((rc+$?))
   done
   return $rc
}

function getCaCert() {
   local rc=0
   local intDir=""
   i=0;while test $((i++)) -lt $NUMINTCAS; do
      ADDR=127.0.${i}.1
      export FABRIC_CA_CLIENT_HOME="$TDIR/int${i}"
      # the location a filename of the returned cert bundle
      intDir="$TDIR/int${i}/msp/cacerts"
      caCertFile=$(echo ${ADDR}|sed 's/\./-/g')-${CA_DEFAULT_PORT}.pem

      /usr/local/bin/fabric-ca-client getcacert \
                      -u ${PROTO}admin:adminpw@$ADDR:${CA_DEFAULT_PORT} \
                      --tls.certfiles $TLSDIR/tlsroots.pem
      # if the file didn't get created, fail
      if ! test -f "$intDir/$caCertFile"; then
         echo "Failed to get cacert"
         return 1
      fi
   done
}

function verifyCaCert() {
   local rc=0
   local intDir=""
   i=0;while test $((i++)) -lt $NUMINTCAS; do
      ADDR=127.0.${i}.1
      # the location and filename of the returned cert bundle
      intDir="$TDIR/int${i}/msp/cacerts"
      caCertFile=$(echo ${ADDR}|sed 's/\./-/g')-${CA_DEFAULT_PORT}.pem
      # verify that the returned bundle contains both the
      # root CA public cert and the intermediate CA public cert
      openssl crl2pkcs7 -nocrl -certfile "$intDir/$caCertFile" |
         openssl pkcs7 -print_certs -noout | sed '/^[[:blank:]]*$/d' |
            awk -F'=' \
                -v rc=0 \
                -v s="intermediateCa${i}" \
                -v i="fabric-ca-server" '
               NR==1 || NR==2 || NR==4 {
                  if ($NF!=i) rc+=1
               }
               NR==3 {
                  if ($NF!=s) rc+=1
               }; END {exit rc}'
      if test "$rc" -ne 0; then
         echo "CA cert bundle $TDIR/int${i}/msp/cacerts/$caCertFile does not contain the correct certificates"
         return 1
      fi
   done
   return $rc
}

function registerAndEnrollUser() {
   local rc=0
   i=0;while test $((i++)) -lt $NUMINTCAS; do
      pswd=$(/usr/local/bin/fabric-ca-client register -u ${PROTO}admin:adminpw@$ADDR:${CA_DEFAULT_PORT} \
                              --id.name user${i} \
                              --id.type user \
                              --id.maxenrollments $MAXENROLL \
                              --id.affiliation org1 \
                              --tls.certfiles $TLSDIR/tlsroots.pem \
                              -c $TDIR/int${i}/register.yaml|tail -n1 | awk '{print $NF}')
      /usr/local/bin/fabric-ca-client enroll \
                         --id.maxenrollments $MAXENROLL \
                         -u ${PROTO}user${i}:$pswd@$ADDR:${CA_DEFAULT_PORT} \
                         -c $TDIR/int${i}/user${i}/enroll.yaml \
                         --tls.certfiles $TLSDIR/tlsroots.pem \
                         --csr.hosts user${i}@fab-client.raleigh.ibm.com \
                         --csr.hosts user${i}.fabric.raleigh.ibm.com,127.37.37.$i
      rc=$((rc+$?))
   done
   return $rc
}

function reenrollUser() {
   local rc=0
   i=0;while test $((i++)) -lt $NUMINTCAS; do
      ADDR=127.0.${i}.1
      /usr/local/bin/fabric-ca-client reenroll \
                         --id.maxenrollments $MAXENROLL \
                         -u ${PROTO}@$ADDR:${CA_DEFAULT_PORT} \
                         -c $TDIR/int${i}/admin/reenroll.yaml \
                         --tls.certfiles $TLSDIR/tlsroots.pem \
                         --csr.hosts admin@fab-client.raleigh.ibm.com \
                         --csr.hosts admin.fabric.raleigh.ibm.com,127.42.42.$i
      rc=$((rc+$?))
   done
   return $rc
}

function genIntCAConfig() {
   cp $TDIR/root/runFabricCaFvt.yaml "$TDIR/intFabricCaFvt.yaml"
   sed -i "s@\(^[[:blank:]]*maxpathlen: \).*@\1 0@
           s@\(^[[:blank:]]*pathlength: \).*@\1 0@
           s@\(^[[:blank:]]*certfile:\).*.pem@\1@
           s@\(^[[:blank:]]*keyfile:\).*.pem@\1@" "$TDIR/intFabricCaFvt.yaml"
}

### Start Test ###
for driver in postgres mysql; do
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $TDIR/root -D -d $driver
   rm -rf $TDIR

   setupTLScerts

   createRootCA || ErrorExit "Failed to create root CA"

   # using the root config as a template, modify pathlen and cert/key
   genIntCAConfig

   createIntCA || ErrorExit "Failed to create $NUMINTCAS intermedeiate CAs"

   # Attempt to enroll with an intermediate CA with pathlen 0 should fail
   createFailingCA || ErrorMsg "Intermediate CA enroll should have failed"
   grep "Policy violation request" $TDIR/int${i}/server.log || ErrorMsg "Policy violation request not found in response"

   # roundrobin through all intermediate servers and grab the cacert
   getCaCert || ErrorExit "Failed to getCaCert(s)"

   # roundrobin through all intermediate servers and grab the cacert
   verifyCaCert || ErrorExit "Failed to verify CaCert(s)"

   # roundrobin through all intermediate servers and enroll a user
   for iter in {0..1}; do
     enrollUser   || ErrorMsg "Failed to enroll users"
   done

   registerAndEnrollUser

   # roundrobin through all intermediate servers and renroll same user
   for iter in {0..1}; do
      reenrollUser || ErrorMsg "Failed to reenroll users"
   done

   $SCRIPTDIR/fabric-ca_setup.sh -L -x $TDIR/root -D -d $driver
   kill $(ps -x -o pid,comm | awk '$2~/fabric-ca-serve/ {print $1}')
done

# If the test failed, leave the results for debugging
test "$RC" -eq 0 && $SCRIPTDIR/fabric-ca_setup.sh -R -x $CA_CFG_PATH -d $driver

### Clean up ###
rm -f $TESTDATA/openssl.cnf.base.req
CleanUp "$RC"
exit $RC
