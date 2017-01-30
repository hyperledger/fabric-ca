#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
FABRIC_CA_EXEC="$FABRIC_CA/bin/fabric-ca"
FABRIC_CA_HOME="$HOME/fabric-ca"
RC=0
URI="localhost:8888"
DB="$TESTDATA/fabric_ca.db"
USERS=("admin" "admin2" "notadmin")
PSWDS=("adminpw" "adminpw2" "pass")
HTTP_PORT="3755"
export FABRIC_CA_HOME="/tmp/${USERS[1]}"

. $SCRIPTDIR/fabric-ca_utils


# Expected codes
            # user  cert
test1Result="1 good"
test2Result="1 revoked"
test3Result="1 revoked"

function testStatus() {
  local user="$1"
  user_status=$(sqlite3 $DB "SELECT * FROM users WHERE (id=\"$user\");")
  cert_status=$(sqlite3 $DB "SELECT * FROM certificates WHERE (id=\"$user\");")
  user_status_code=$(echo $user_status | awk -F'|' '{print $6}')
  cert_status_code=$(echo $cert_status | awk -F'|' '{print $5}')
  echo "$user_status_code $cert_status_code"
}

cd $TESTDATA
python -m SimpleHTTPServer $HTTP_PORT &
HTTP_PID=$!
pollServer python localhost "$HTTP_PORT" || ErrorExit "Failed to start HTTP server"
echo $HTTP_PID
trap "kill $HTTP_PID; CleanUp" INT


# Kill any running servers
$SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_HOME

# Setup CA server
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X

# Enroll
i=-1
while test $((i++)) -lt 2; do
   FABRIC_CA_HOME="/tmp/${USERS[i]}"
   $SCRIPTDIR/enroll.sh -u "${USERS[i]}" -p "${PSWDS[i]}" -x "/tmp/${USERS[i]}"
done

# notadmin cannot revoke
FABRIC_CA_HOME="/tmp/${USERS[2]}"
$FABRIC_CA_EXEC client revoke $URI ${USERS[2]}
test "$?" -eq 0 && ErrorMsg "Non-revoker successfully revoked cert"

# Check the DB contents
test "$(testStatus ${USERS[0]})" = "$test1Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[0]}" RC
test "$(testStatus ${USERS[1]})" = "$test1Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[1]}" RC

# Grab the serial number of admin cert (convert to decimal)
SN=$(echo "ibase=16;$(openssl x509 -noout -serial -in /tmp/${USERS[0]}/cert.pem | awk -F'=' '{print $2}')" | bc)
# and the auth keyid of admin cert - translate upper to lower case
AKI=$(openssl x509 -noout -text -in /tmp/${USERS[0]}/cert.pem |awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print tolower($0)}')

# Revoke the certs
FABRIC_CA_HOME="/tmp/${USERS[0]}"
#### Blanket all of admin2 certs
$FABRIC_CA_EXEC client revoke $URI ${USERS[1]}
#### Revoke admin's cert by serial number and authority keyid
$FABRIC_CA_EXEC client revoke -serial $SN -aki $AKI $URI ${USERS[0]}

# Verify the DB update
test "$(testStatus ${USERS[0]})" = "$test2Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[0]}" RC
test "$(testStatus ${USERS[1]})" = "$test2Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[1]}" RC

# Veriy that the cert is no longer usable
FABRIC_CA_HOME="/tmp/${USERS[0]}"
$SCRIPTDIR/register.sh -u 'user100'
FABRIC_CA_HOME="/tmp/${USERS[0]}"
test "$?" -eq 0 && ErrorMsg "${USERS[0]} authenticated with revoked certificate" RC
FABRIC_CA_HOME="/tmp/${USERS[1]}"
$SCRIPTDIR/register.sh -u 'user101'
test "$?" -eq 0 && ErrorMsg "${USERS[1]} authenticated with revoked certificate" RC

# Verify the DB update
test "$(testStatus ${USERS[0]})" = "$test3Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[0]}" RC
test "$(testStatus ${USERS[1]})" = "$test3Result" ||
   ErrorMsg "Incorrect user/certificate status for ${USERS[1]}" RC

CleanUp $RC
kill $HTTP_PID
wait $HTTP_PID
exit $RC
