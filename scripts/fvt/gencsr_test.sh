#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE:=gencsr}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
CA_CFG_PATH="/tmp/$TESTCASE"
ADMINUSER="admin"
USERDIR="$CA_CFG_PATH/$ADMINUSER"
CONFIGFILE="$USERDIR/fabric-ca-client-config.yaml"
ADMINCERT="$USERDIR/admincert.pem"
CSR=$CA_CFG_PATH/$ADMINUSER/msp/signcerts/$ADMINUSER.csr
. $SCRIPTDIR/fabric-ca_utils
RC=0
export CA_CFG_PATH
rm -rf /tmp/${TESTCASE}
rm -rf /tmp/CAs/${TESTCASE}

function signReq() {
   # sign CSR
   HOME=$CA_CFG_PATH/$ADMINUSER reqout=$CSR \
   /etc/hyperledger/fabric-ca/pki -f signreq -a $TESTCASE -p $ADMINUSER <<EOF
y
y
EOF
}

function verifyResult() {
   artifact="$1"
   expected_subject="$2"
   case $artifact in
      cert)  actual_subject="$(openssl x509 -in $ADMINCERT -noout -subject -nameopt rfc2253 |sed 's/subject=//')"
      ;;
      csr) actual_subject="$(openssl req -in $CSR -noout -subject -nameopt rfc2253 |sed 's/subject=//')"
      ;;
   esac
   echo expected_subject: $expected_subject
   test "$expected_subject" = "$actual_subject" || ErrorMsg "expected \n\"$expected_subject\"\n found \"$actual_subject\""
}

# Create a new external PKI CA
/etc/hyperledger/fabric-ca/pki -f newca -a $TESTCASE

# supply CN at the command line
expected="CN=$ADMINUSER,OU=Fabric,O=Hyperledger,ST=North Carolina,C=US"
fabric-ca-client gencsr --csr.cn "$ADMINUSER" -H $CA_CFG_PATH/$ADMINUSER
openssl req -noout -in /tmp/gencsr/admin/msp/signcerts/admin.csr -subject | sed 's/subject=//'
openssl req -noout -in $CSR -subject | sed 's/subject=//'
verifyResult csr "$expected"
signReq
verifyResult cert "$expected"

# supply CN from a file
sed -i "s/cn:.*/cn: $ADMINUSER/" $USERDIR/fabric-ca-client-config.yaml | grep cn:
fabric-ca-client gencsr -H $CA_CFG_PATH/$ADMINUSER
openssl req -noout -in /tmp/gencsr/admin/msp/signcerts/admin.csr -subject | sed 's/subject=//'
openssl req -noout -in $CSR -subject | sed 's/subject=//'
verifyResult csr "$expected"
signReq
verifyResult cert "$expected"

# CN from command line overrides file
CSR=$CA_CFG_PATH/$ADMINUSER/msp/signcerts/new$ADMINUSER.csr
expected="CN=new$ADMINUSER,OU=Fabric,O=Hyperledger,ST=North Carolina,C=US"
fabric-ca-client gencsr --csr.cn "new$ADMINUSER" -H $CA_CFG_PATH/$ADMINUSER
openssl req -noout -in /tmp/gencsr/admin/msp/signcerts/admin.csr -subject | sed 's/subject=//'
openssl req -noout -in $CSR -subject | sed 's/subject=//'
verifyResult csr "$expected"
signReq
verifyResult cert "$expected"

## Supply names from file
sed -i "s/C:.*/C: FR/
        s/ST:.*/ST: Cantal/
        s/ST:.*/ST: Cantal/
        s/L:.*/L: Salers/
        s/O:.*/O: Gourmet/
        s/serialnumber:.*/serialnumber: ABCDEFGHIJKLMNOPQRSTUVWXYZ/" $USERDIR/fabric-ca-client-config.yaml
CSR=$CA_CFG_PATH/$ADMINUSER/msp/signcerts/$ADMINUSER.csr
expected="serialNumber=ABCDEFGHIJKLMNOPQRSTUVWXYZ,CN=admin,OU=Fabric,O=Gourmet,L=Salers,ST=Cantal,C=FR"
fabric-ca-client gencsr -H $CA_CFG_PATH/$ADMINUSER
openssl req -noout -in /tmp/gencsr/admin/msp/signcerts/admin.csr -subject | sed 's/subject=//'
openssl req -noout -in $CSR -subject | sed 's/subject=//'
verifyResult csr "$expected"
signReq
verifyResult cert "$expected"
cat  $USERDIR/fabric-ca-client-config.yaml
# Names from command line overrides file
CSR=$CA_CFG_PATH/$ADMINUSER/msp/signcerts/$ADMINUSER.csr
expected='serialNumber=0123456789,CN=admin,OU=Vieux,O=Moulin,L=Charleville-M\C3\A9zi\C3\A8rs,ST=Ardennes,C=FR'
fabric-ca-client gencsr --csr.names C=FR,ST=Ardennes,L=Charleville-Mézièrs,O=Moulin,OU=Vieux \
                        --csr.hosts 1.1.1.1,::1,example.com,me@example.com \
                        --csr.serialnumber "0123456789" \
                        --csr.cn admin \
                        -H $CA_CFG_PATH/$ADMINUSER
openssl req -noout -in /tmp/gencsr/admin/msp/signcerts/admin.csr -subject | sed 's/subject=//'
openssl req -noout -in $CSR -subject | sed 's/subject=//'
verifyResult csr "$expected"
signReq
verifyResult cert "$expected"

CleanUp $RC
exit $RC
