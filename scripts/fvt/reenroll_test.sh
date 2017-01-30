#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
KEYSTORE="/tmp/keyStore"
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

function enrollUser() {
   local USERNAME=$1
   mkdir -p $KEYSTORE/$USERNAME
   export FABRIC_CA_HOME=$KEYSTORE/$REGISTRAR
   OUT=$($SCRIPTDIR/register.sh -u $USERNAME -t $USERTYPE -g $USERGRP -x $FABRIC_CA_HOME)
   echo "$OUT"
   PASSWD="$(echo "$OUT" | head -n1 | awk '{print $NF}')"
   export FABRIC_CA_HOME=$KEYSTORE/$USERNAME
   test -d $FABRIC_CA_HOME || mkdir -p $FABRIC_CA_HOME
   $SCRIPTDIR/enroll.sh -u $USERNAME -p $PASSWD -x $FABRIC_CA_HOME
}

while getopts "du:t:k:l:" option; do
  case "$option" in
     d)   FABRIC_CA_DEBUG="true" ;;
     u)   USERNAME="$OPTARG" ;;
     t)   USERTYPE="$OPTARG" ;;
     g)   USERGRP="$OPTARG" ;;
     k)   KEYTYPE="$OPTARG" ;;
     l)   KEYLEN="$OPTARG" ;;
  esac
done

: ${FABRIC_CA_DEBUG="false"}
: ${USERNAME="newclient"}
: ${USERTYPE="client"}
: ${USERGRP="bank_a"}
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}
: ${HOST="localhost:10888"}

HTTP_PORT="3755"

rm -rf $CERT_HOME/ROOT_CERT $HOME/ROOT_CERT*
rm -rf $CERT_HOME/UNSUPPORTED $HOME/UNSUPPORTED-
$PKI -f newca   -d sha256 -a ROOT_CERT -t ec -l 256 ROOT_CERT -n "/CN=ROOT_CERT/"
$PKI -f newcert -d sha256 -a ROOT_CERT -t ec -l 256 -p UNSUPPORTED- -n "/CN=UNSUPPORTED/" <<EOF
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
trap "kill $HTTP_PID; CleanUp" INT

export FABRIC_CA_DEBUG
mkdir -p $KEYSTORE/$REGISTRAR
export FABRIC_CA_HOME=$KEYSTORE/$REGISTRAR
test -d $FABRIC_CA_HOME || mkdir -p $FABRIC_CA_HOME

#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do
   echo ""
   echo ""
   echo ""
   echo "------> BEGIN TESTING $driver <----------"
   # note MAX_ENROLLMENTS defaults to '1'
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $KEYSTORE
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -n4 -d $driver
   if test $? -ne 0; then
      ErrorMsg "Failed to setup server"
      continue
   fi

   FABRIC_CA_HOME=$KEYSTORE/$REGISTRAR
   $SCRIPTDIR/enroll.sh -u $REGISTRAR -p $REGISTRARPWD -x $FABRIC_CA_HOME
   if test $? -ne 0; then
      ErrorMsg "Failed to enroll $REGISTRAR"
      continue
   fi

   for i in {1..4}; do
      enrollUser user${i}
      if test $? -ne 0; then
         echo "Failed to enroll user${i}"
      else
         FABRIC_CA_HOME=$KEYSTORE/user${i}
         test -d $FABRIC_CA_HOME || mkdir -p $FABRIC_CA_HOME
         # user can be reenrolled even though MAX_ENROLLMENTS set to '1'
         $SCRIPTDIR/reenroll.sh -x $FABRIC_CA_HOME
         test $? -ne 0 && ErrorMsg "Failed to reenroll user${i}"
      fi
      sleep 1
   done

   # sqaure up the number of requests to each of 4 servers
   $SCRIPTDIR/reenroll.sh -x /tmp/keyStore/$REGISTRAR
   $SCRIPTDIR/reenroll.sh -x /tmp/keyStore/$REGISTRAR
   $SCRIPTDIR/reenroll.sh -x /tmp/keyStore/$REGISTRAR
   # all servers should register 4 successful requests
   # but...it's only available when tls is disabled
   if test "$FABRIC_TLS" = 'false'; then
      for s in {1..4}; do
         curl -s http://${HOST}/ | awk -v s="server${s}" '$0~s'|html2text|grep HTTP
         verifyServerTraffic $HOST server${s} 4
         test $? -ne 0 && ErrorMsg echo "Distributed traffic to server FAILED"
         sleep 1
      done
   fi

   #for cert in EXPIRED UNRIPE UNSUPPORTED; do
   for cert in EXPIRED UNRIPE ; do
      FABRIC_CA_HOME=$KEYSTORE/user1
      cat $HOME/${cert}-cert.pem |sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > $FABRIC_CA_HOME/cert.pem
      cat $HOME/${cert}-key.pem | openssl ec -outform pem -out $FABRIC_CA_HOME/key.pem
      #cp $HOME/${cert}-key.pem  $FABRIC_CA_HOME/key.pem
      openssl ec -in $FABRIC_CA_HOME/key.pem -text
      openssl x509 -in $FABRIC_CA_HOME/cert.pem -text
      $SCRIPTDIR/reenroll.sh -x $FABRIC_CA_HOME
      test $? -eq 0 && ErrorMsg "reenrolled user1 with unsupported cert"
   done
   $SCRIPTDIR/fabric-ca_setup.sh -R -x $KEYSTORE
   echo "------> END TESTING $driver <----------"
   echo "***************************************"
   echo ""
   echo ""
   echo ""
   echo ""
done

kill $HTTP_PID
wait $HTTP_PID
CleanUp $RC
exit $RC
