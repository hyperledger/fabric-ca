#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
PKI="$SCRIPTDIR/utils/pki"
CERT_HOME="/tmp/CAs/"
REGISTRAR="admin"
REGISTRARPWD="adminpw"
RC=0

curr_year=$(date +"%g")
prev_year=$((curr_year-1))
next_year=$((curr_year+1))

past=$(date +"$prev_year%m%d%H%M%SZ")
now=$(date +"%g%m%d%H%M%SZ")
future=$(date +"$next_year%m%d%H%M%SZ")

. $SCRIPTDIR/fabric-ca_utils

while getopts "dx:" option; do
  case "$option" in
     d)   FABRIC_CA_DEBUG="true" ;;
     x)   CA_CFG_PATH="$OPTARG" ;;
  esac
done

: ${CA_CFG_PATH:="/tmp/reenroll"}
: ${FABRIC_CA_DEBUG="false"}
: ${HOST="localhost:10888"}
export CA_CFG_PATH
export FABRIC_CA_CLIENT_HOME="$CA_CFG_PATH/admin"

HTTP_PORT="3755"

rm -rf $CERT_HOME/ROOT_CERT $HOME/ROOT_CERT*
rm -rf $CERT_HOME/UNSUPPORTED $HOME/UNSUPPORTED-
$PKI -f newca   -d sha256 -a ROOT_CERT -t ec -l 256 ROOT_CERT -n "/CN=ROOT_CERT/"
$PKI -f newcert -d sha256 -a ROOT_CERT -t dsa -l 256 -p UNSUPPORTED- -n "/CN=UNSUPPORTED/" <<EOF
y
y
EOF
$PKI -f newcert -e $past -d sha256 -a ROOT_CERT -t ec -l 256 -p EXPIRED- -n "/CN=EXPIRED/" <<EOF
y
y
EOF
$PKI -f newcert -s $future -d sha256 -a ROOT_CERT -t ec -l 256 -p UNRIPE- -n "/CN=UNRIPE/" <<EOF
y
y
EOF

test -f "$CERT_HOME" || mkdir -p "$CERT_HOME"
cd $CERT_HOME
cp $TESTDATA/TestCRL.crl $CERT_HOME
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp 1; exit 1" INT

export FABRIC_CA_DEBUG
for driver in sqlite3 postgres mysql; do
   echo ""
   echo ""
   echo ""
   echo "------> BEGIN TESTING $driver <----------"
   # note MAX_ENROLLMENTS defaults to '1'
   $SCRIPTDIR/fabric-ca_setup.sh -R -d $driver -x $CA_CFG_PATH
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n4 -d $driver -x $CA_CFG_PATH
   if test $? -ne 0; then
      ErrorMsg "Failed to setup server"
      continue
   fi
   enroll $REGISTRAR
   if test $? -ne 0; then
      ErrorMsg "Failed to enroll $REGISTRAR"
      continue
   fi

   for i in {1..4}; do
      OUT=$(register $REGISTRAR user${i})
      pswd[$i]=$(echo $OUT | tail -n1 | awk '{print $NF}')
      echo $pswd
   done

   for i in {1..4}; do
      enroll user${i} ${pswd[i]}
      test $? -ne 0 && ErrorMsg "Failed to reenroll user${i}"
   done

   for i in 1 2 3 4 1 2 3; do
      # sqaure up the number of requests to each of 4 servers by additional requests
       reenroll user${i} "$CA_CFG_PATH/user${i}/$MSP_CERT_DIR/cert.pem" "$CA_CFG_PATH/user${i}/$MSP_KEY_DIR/key.pem"
       test $? -ne 0 && ErrorMsg "Failed to reenroll user${i}"
   done
   # all servers should register 4 successful requests
   # but...it's only available when tls is disabled
   if test "$FABRIC_TLS" = 'false'; then
      for s in {1..4}; do
         curl -s http://${HOST}/ | awk -v s="server${s}" '$0~s'|html2text|grep HTTP
         verifyServerTraffic $HOST server${s} 4
         test $? -ne 0 && ErrorMsg "Distributed traffic to server FAILED"
         sleep 1
      done
   fi

   keyStore="$CA_CFG_PATH/user1/$MSP_KEY_DIR"
   certStore="$CA_CFG_PATH/user1/$MSP_CERT_DIR"
   for cert in EXPIRED UNRIPE UNSUPPORTED; do
      openssl x509 -in $HOME/${cert}-cert.pem -out  $certStore/cert.pem
      openssl ec -in $HOME/${cert}-key.pem -out $keyStore/key.pem
      openssl ec -in $keyStore/key.pem -text
      openssl x509 -in $certStore/cert.pem -text
      reenroll user1 "$CA_CFG_PATH/user1/$MSP_CERT_DIR/cert.pem" "$CA_CFG_PATH/user1/$MSP_KEY_DIR/key.pem"
      test $? -eq 0 && ErrorMsg "reenrolled user1 with unsupported cert"
   done
   $SCRIPTDIR/fabric-ca_setup.sh -L -d $driver
   echo "------> END TESTING $driver <----------"
   echo "***************************************"
   echo ""
   echo ""
   echo ""
   echo ""
done
$SCRIPTDIR/fabric-ca_setup.sh -R -d $driver -x $CA_CFG_PATH

kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
