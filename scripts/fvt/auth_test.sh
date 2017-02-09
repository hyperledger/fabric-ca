#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
SERVERCONFIG="/tmp/config.json.$RANDOM"

if test -n "$TLS_ON"; then
   TLS_DISABLE='false'
else
   case "$FABRIC_TLS" in
      true) TLS_DISABLE='false' ;;
     false) TLS_DISABLE='true'  ;;
         *) TLS_DISABLE='true'  ;;
   esac
fi

# default value
cat > "$SERVERCONFIG" <<EOF
{
 "tls_disable":$TLS_DISABLE,
 "driver":"sqlite3",
 "data_source":"fabric_ca.db",
 "ca_cert":"/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/fabric-ca-cert.pem",
 "ca_key":"/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/fabric-ca-key.pem",
 "tls":{
   "tls_cert":"/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/tls_server-cert.pem",
   "tls_key":"/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/tls_server-key.pem",
   "mutual_tls_ca":"/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/root.pem",
   "db_client":{
     "ca_certfiles":["/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/root.pem"],
     "client":{"keyfile":"/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/tls_server-key.pem","certfile":"/home/ibmadmin/gopath/src/github.com/hyperledger/fabric-ca/testdata/tls_server-cert.pem"}
   }
 },
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
   test $? -ne 0 && ErrorMsg "Failed to enroll admin"
   # Fail case - send null passwd
   $SCRIPTDIR/enroll.sh -u admin -p ""
   test $? -eq 0 && ErrorMsg "Improperly enrolled admin with null passwd"
   # Fail case - send bogus passwd
   $SCRIPTDIR/enroll.sh -u admin -p xxxxxx
   test $? -eq 0 && ErrorMsg "Improperly enrolled admin with bad passwd"

   # - auth disabled
   $SCRIPTDIR/fabric-ca_setup.sh  -R
   $SCRIPTDIR/fabric-ca_setup.sh  -A -I -S -X -d $driver
   test $? -ne 0 && ErrorExit "Failed to setup server"
   # Success case - send correct passwd
   $SCRIPTDIR/enroll.sh -u admin -p adminpw
   test $? -ne 0 && ErrorMsg "Authentication disabled: failed to enroll admin with vaild passwd"
   # Success case - send null passwd
   $SCRIPTDIR/enroll.sh -u admin -p ""
   test $? -ne 0 && ErrorMsg "Authentication disabled: failed to enroll admin with null passwd"
   # Success case - send bogus passwd
   $SCRIPTDIR/enroll.sh -u admin -p xxxxxx
   test $? -ne 0 && ErrorMsg "Authentication disabled: failed to enroll admin with bad passwd"

   # - default (auth enabled)
   $SCRIPTDIR/fabric-ca_setup.sh  -R
   $SCRIPTDIR/fabric-ca_setup.sh  -I -S -X -d $driver -g "$SERVERCONFIG"
   test $? -ne 0 && ErrorExit "Failed to setup server"
   # Success case - send passwd
   $SCRIPTDIR/enroll.sh -u admin -p adminpw
   test $? -ne 0 && ErrorMsg "Failed to enroll admin"
   # Fail case - send null passwd
   $SCRIPTDIR/enroll.sh -u admin -p ""
   test $? -eq 0 && ErrorMsg "Improperly enrolled admin with null passwd"
   # Fail case - send bogus passwd
   $SCRIPTDIR/enroll.sh -u admin -p xxxxxx
   test $? -eq 0 && ErrorMsg "Improperly enrolled admin with bad passwd"

done
rm $SERVERCONFIG
CleanUp $RC
exit $RC
