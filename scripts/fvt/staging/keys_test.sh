#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
TESTDATA="$FABRIC_CA/testdata"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
CA_KEY="$TESTDATA/fabric-ca-key.pem"
EE_KEY="$HOME/fabric-ca/key.pem"
EE_CERT="$HOME/abric-ca/cert.pem"
RC=0
. $SCRIPTDIR/fabric-ca_utils

ecl=(256 384 521)
ecl=256
ecOid[256]="prime256v1"
ecOid[384]="secp384r1"
ecOid[521]="secp521r1"
rsal=(2048 3072 4096)

function VerifyKey() {
   local key=$1
   local ktype=$2
   local klen=$3
   local koid=$4
   local sslcmd=rsa

   test $ktype = "rsa" || sslcmd="ec"
   openssl $sslcmd -in $key -text 2>/dev/null|
      awk -v kt=$koid -v kl=$klen -v rc=0 '
         $1~/Private-Key/ {gsub(/\(/,"");l=$2}
         $0~/ASN1 OID/ {k=$3}
         END {
                if (kt!=k) { print "Wrong keytype...FAILED"; rc+=1 }
                if (kl!=l) { print "Wrong keylength...FAILED"; rc+=1 }
                exit rc
         }'
   return $?
}


echo "------> Testing EC varitions"
ktype=ecdsa
for len in ${ecl[*]}; do
   echo "------> Testing keylenth $len"
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -X -S -n 1 -t $ktype -l $len
   # verify CA key type and length
   VerifyKey $CA_KEY $ktype $len ${ecOid[$len]} || ErrorMsg "VerifyKey CA $ktype $len failed"
   $SCRIPTDIR/enroll.sh -t $ktype -l $len
   # verify EE key type and length
   VerifyKey $EE_KEY $ktype $len ${ecOid[$len]} || ErrorMsg "VerifyKey EE $ktype $len failed"
done
ktype=rsa
echo ""
echo "**********************************************"
echo ""
echo "------> Testing RSA varitions"
for len in ${rsal[*]}; do
   echo "------> Testing keylenth $len"
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -X -S -n 1 -t $ktype -l $len
   # verify CA key type and length
   VerifyKey $CA_KEY $ktype $len "" || ErrorMsg "VerifyKey CA $ktype $len failed"
   $SCRIPTDIR/enroll.sh -t $ktype -l $len
   # verify EE key type and length
   VerifyKey $EE_KEY $ktype $len "" || ErrorMsg "VerifyKey CA $ktype $len failed"
   echo ""
   echo ""
done

echo ""
echo "**********************************************"
echo ""

$SCRIPTDIR/fabric-ca_setup.sh -R
CleanUp $RC
exit $RC
