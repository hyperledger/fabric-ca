#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
HOST="localhost:10888"
SERVERCONFIG="/tmp/config.json.$RANDOM"

# default value
cat > "$SERVERCONFIG" <<EOF
{
 "tls_disable":true,
 "driver":"sqlite3",
 "data_source":"fabric-ca.db",
 "users": {
    "admin": {
      "pass": "adminpw",
      "type": "client",
      "group": "bank_a",
      "attrs": [{"name":"hf.Registrar.Roles","value":"client,user,peer,validator,auditor"},
                {"name":"hf.Registrar.DelegateRoles", "value": "client,user,validator,auditor"},
                {"name":"hf.Revoker", "value": "true"}]
    }
 },
 "groups": {
   "banks_and_institutions": {
     "banks": ["bank_a"]
   }
 },
 "signing": {
    "default": {
       "usages": ["cert sign"],
       "expiry": "8000h",
       "ca_constraint": {"is_ca": true, "max_path_len":1},
       "ocsp_no_check": true,
       "not_before": "2016-12-30T00:00:00Z"
    },
    "expiry": {
       "usages": ["cert sign"],
       "expiry": "1s"
    }
 }
}
EOF
trap "rm $SERVERCONFIG; CleanUp" INT
#for driver in sqlite3 postgres mysql; do
for driver in sqlite3 ; do

   # - auth enabled
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -d $driver
   test $? -ne 0 && ErrorExit "Failed to setup server"
   # Success case - send passwd
   $SCRIPTDIR/enroll.sh -u admin -p adminpw
   RC=$((RC+$?))
   # Fail case - send null passwd
   $SCRIPTDIR/enroll.sh -u admin -p ""
   test $? -eq 0 && RC=$((RC+1))
   # Fail case - send bogus passwd
   $SCRIPTDIR/enroll.sh -u admin -p xxxxxx
   test $? -eq 0 && RC=$((RC+1))

   # - auth disabled
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -A -I -S -X -d $driver
   # Success case - send correct passwd
   $SCRIPTDIR/enroll.sh -u admin -p adminpw
   RC=$((RC+$?))
   # Success case - send null passwd
   $SCRIPTDIR/enroll.sh -u admin -p ""
   RC=$((RC+$?))
   # Success case - send bogus passwd
   $SCRIPTDIR/enroll.sh -u admin -p xxxxxx
   RC=$((RC+$?))

   # - default (auth enabled)
   $SCRIPTDIR/fabric-ca_setup.sh -R
   $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -d $driver -g "$SERVERCONFIG"
   test $? -ne 0 && ErrorExit "Failed to setup server"
   # Success case - send passwd
   $SCRIPTDIR/enroll.sh -u admin -p adminpw
   RC=$((RC+$?))
   # Fail case - send null passwd
   $SCRIPTDIR/enroll.sh -u admin -p ""
   test $? -eq 0 && RC=$((RC+1))
   # Fail case - send bogus passwd
   $SCRIPTDIR/enroll.sh -u admin -p xxxxxx
   test $? -eq 0 && RC=$((RC+1))

done
rm $SERVERCONFIG
CleanUp $RC
exit $RC
