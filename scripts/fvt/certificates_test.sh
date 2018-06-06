#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE:="certificates"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
TESTDATA="$FABRIC_CA/testdata"
. $SCRIPTDIR/fabric-ca_utils
RC=0

USERNAME="admin"
USERPSWD="adminpw"

DBNAME=fabric_ca

function postgresDBCleanup() {
    psql -d $DBNAME -c "TRUNCATE TABLE certificates" &> /dev/null
}

function populatePostgresCertsTable() {
    # Expired and Not Revoked
    insertCertsTable "user1" "1111" "2222" "11/18/2017" "01/01/0001"
    insertCertsTable "user2" "1112" "2223" "1/18/2018" "01/01/0001"
    insertCertsTable "user3" "1111" "2223" "1/18/2018" "01/01/0001"
    insertCertsTable "user3" "1111" "2224" "1/18/2018" "01/01/0001"
    insertCertsTable "user4" "1113" "2224" "1/25/2018" "01/01/0001"

    # Not Expired and Not Revoked
    NewDate=$(date "+%Y-%m-%d %H:%M:%S" -d "+20 days")
    insertCertsTable "user5" "1114" "2225" "$NewDate" "01/01/0001"

    # Revoked and Not Expired
    insertCertsTable "user5" "1115" "2225" "$NewDate" "2/18/2018"
    insertCertsTable "user6" "1116" "2225" "$NewDate" "2/18/2017"
    insertCertsTable "user7" "1117" "2225" "$NewDate" "1/18/2018"

    # Revoked and Expired
    insertCertsTable "user8" "1118" "2225" "1/30/2018" "1/18/2018"
}

function insertCertsTable() {
    local id="$1"
    local serial="$2"
    local aki="$3"
    local expiry="$4"
    local revokedAt="$5"

    # Generate certificates with the common name set to a user
    echo "Generating certificate for $id"
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=$id"
    pem=`cat cert.pem`

    # Store the generated certificate in the certificates table
    psql -d $DBNAME -c "INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem, level) VALUES ('$id', '$serial', '$aki', 'ca', 'active', '0', '$expiry', '$revokedAt', '$pem', '1')"
}

function assertContainsUserCert() {
    local testing="$1"
    shift
    local users=("$@")

    for i in "${users[@]}"; do
        grep "$i" output.txt
        test $? == 0 || ErrorMsg "Failed to complete 'certificates list' command with '$testing' flags, $i certificate not returned"
    done

}

function assertNotContainsUserCert() {
    local testing="$1"
    shift
    local users=("$@")

    for i in "${users[@]}"; do
        grep "$i" output.txt
        test $? == 1 || ErrorMsg "Incorrect results using 'certificate list' command with '$testing' flags, $i certificate should not be returned"
    done
}

function assertNumberOfCerts() {
    local count=$1
    tail -n 5 server.txt | grep "Number of certificates found: $count"
    test $? == 0 || ErrorMsg "Failed return correct number of certificates, expecting $count"
}

#####################################################################
# Testing Certificates API with Postgres
#####################################################################

###### Start Fabric CA Server with Postgres Database #######

postgresDBCleanup
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d postgres 2>&1 | tee server.txt &
pollFabricCa
populatePostgresCertsTable

#### Enroll user first, so subsequent commands can be called ####
$FABRIC_CA_CLIENTEXEC enroll -u "http://$USERNAME:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME
if [ $? != 0 ]; then
    ErrorMsg "Failed to enroll user"
fi

#### Test various filters for the list certificates commands #####

## List all certificates ##
$FABRIC_CA_CLIENTEXEC certificate list -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "all" user1 user2 user3 user4 user5 user6 user7 user8
assertNumberOfCerts 11

## List certificate by ID ##

$FABRIC_CA_CLIENTEXEC certificate list --id user1 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--id" user1
assertNumberOfCerts 1

## List certificate by Serial Number ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 -H $CA_CFG_PATH/$USERNAME > output.txt
users=(user1 user3)
assertContainsUserCert "--serial" user1 user3
assertNumberOfCerts 3

## List certificate by Serial Number and ID ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 --id user1 -H $CA_CFG_PATH/$USERNAME --store $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--serial --id" user1
assertNotContainsUserCert "--serial --id" user3
assertNumberOfCerts 1
if [ ! -f $CA_CFG_PATH/$USERNAME/user1.pem ]; then
    ErrorMsg "Failed to store certificate in the specified location"
fi

## List certificate by AKI ##

$FABRIC_CA_CLIENTEXEC certificate list --aki 2223 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--aki" user2 user3
assertNumberOfCerts 2

## List certificate by Serial Number, AKI, and ID ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 --aki 2224 --id user3 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--serial --aki --id" user3
assertNumberOfCerts 1
grep "2223" output.txt
test $? == 1 || ErrorMsg "Incorrectly got certificate for 'user3'"

## List certificate within expiration range ##

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-03-01:: -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration date::" user5 user6 user7
assertNotContainsUserCert "--expiration date::" user1 user2 user3 user4
assertNumberOfCerts 5

$FABRIC_CA_CLIENTEXEC certificate list --expiration ::2018-01-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration ::date" user1
assertNotContainsUserCert "--expiration ::date" user2
assertNumberOfCerts 1

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-01::2018-03-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration date1::date2" user2 user3 user4 user8
assertNotContainsUserCert "--expiration data1::date2" user1
assertNumberOfCerts 5

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-01::2018-03-01 --id user3 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration date1::date2" user3
assertNotContainsUserCert "--expiration date1::date2" user2
assertNumberOfCerts 2

## List certificate within revocation range ##

$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-02-01:: -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation date::" user5
assertNumberOfCerts 1

$FABRIC_CA_CLIENTEXEC certificate list --revocation ::2018-01-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation ::date" user6
assertNotContainsUserCert "--revocation ::date" user5
assertNumberOfCerts 1

$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-01-01::2018-02-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation date1::date2" user7
assertNotContainsUserCert "--revocation data1::date2" user5 user6
assertNumberOfCerts 2

## List certificates within expiration range but have not been revoked ##
$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-20::2018-01-30 --notrevoked -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration --notrevoekd" user4
assertNotContainsUserCert "--expiration --notrevoked" user8
assertNumberOfCerts 1

## List certificates within revocation range but have not expired ##
$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-01-01::2018-01-30 --notexpired -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation --notexpired" user7
assertNotContainsUserCert "--revocation --notexpired" user8
assertNumberOfCerts 1

$SCRIPTDIR/fabric-ca_setup.sh -K
postgresDBCleanup

#####################################################################
# Testing Certificates API with PostgreSQL - Complete
#####################################################################

function mysqlDBCleanup() {
    mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "TRUNCATE TABLE certificates" &> /dev/null
}

function populateMySQLCertsTable() {
    # Expired and Not Revoked
    insertMySQLCertsTable "user1" "1111" "2222" "2017/11/18" "0000/00/00"
    insertMySQLCertsTable "user2" "1112" "2223" "2018/01/18" "0000/00/00"
    insertMySQLCertsTable "user3" "1111" "2223" "2018/01/18" "0000/00/00"
    insertMySQLCertsTable "user3" "1111" "2224" "2018/01/18" "0000/00/00"
    insertMySQLCertsTable "user4" "1113" "2224" "2018/01/25" "0000/00/00"

    # Not Expired and Not Revoked
    NewDate=$(date "+%Y-%m-%d %H:%M:%S" -d "+20 days")
    insertMySQLCertsTable "user5" "1114" "2225" "$NewDate" "0000/00/00"

    # Revoked and Not Expired
    insertMySQLCertsTable "user5" "1115" "2225" "$NewDate" "2018/02/18"
    insertMySQLCertsTable "user6" "1116" "2225" "$NewDate" "2017/02/18"
    insertMySQLCertsTable "user7" "1117" "2225" "$NewDate" "2018/01/18"

    # Revoked and Expired
    insertMySQLCertsTable "user8" "1118" "2225" "2018/01/30" "2018/01/18"
}

function insertMySQLCertsTable() {
    local id="$1"
    local serial="$2"
    local aki="$3"
    local expiry="$4"
    local revokedAt="$5"

    # Generate certificates with the common name set to a user
    echo "Generating certificate for $id"
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=$id"
    pem=`cat cert.pem`

    # Store the generated certificate in the certificates table
    mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "INSERT INTO certificates (id, serial_number, authority_key_identifier, ca_label, status, reason, expiry, revoked_at, pem, level) VALUES ('$id', '$serial', '$aki', 'ca', 'active', '0', '$expiry', '$revokedAt', '$pem', '1')"
}

#####################################################################
# Testing Certificates API with MySQL
#####################################################################

###### Start Fabric CA Server with MySQL Database #######

mysqlDBCleanup
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d mysql 2>&1 | tee server.txt &
pollFabricCa
populateMySQLCertsTable

#### Enroll user first, so subsequent commands can be called ####
$FABRIC_CA_CLIENTEXEC enroll -u "http://$USERNAME:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME
if [ $? != 0 ]; then
    ErrorMsg "Failed to enroll user"
fi

#### Test various filters for the list certificates commands #####

## List all certificates ##
$FABRIC_CA_CLIENTEXEC certificate list -H $CA_CFG_PATH/$USERNAME 2>&1 | tee output.txt
assertContainsUserCert "all" user1 user2 user3 user4 user5 user6 user7 user8
assertNumberOfCerts 11

## List certificate by ID ##

$FABRIC_CA_CLIENTEXEC certificate list --id user1 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--id" user1
assertNumberOfCerts 1

## List certificate by Serial Number ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 -H $CA_CFG_PATH/$USERNAME > output.txt
users=(user1 user3)
assertContainsUserCert "--serial" user1 user3
assertNumberOfCerts 3

## List certificate by Serial Number and ID ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 --id user1 -H $CA_CFG_PATH/$USERNAME --store $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--serial --id" user1
assertNotContainsUserCert "--serial --id" user3
assertNumberOfCerts 1
if [ ! -f $CA_CFG_PATH/$USERNAME/user1.pem ]; then
    ErrorMsg "Failed to store certificate in the specified location"
fi

## List certificate by AKI ##

$FABRIC_CA_CLIENTEXEC certificate list --aki 2223 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--aki" user2 user3
assertNumberOfCerts 2

## List certificate by Serial Number, AKI, and ID ##

$FABRIC_CA_CLIENTEXEC certificate list --serial 1111 --aki 2224 --id user3 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--serial --aki --id" user3
assertNumberOfCerts 1
grep "2223" output.txt
test $? == 1 || ErrorMsg "Incorrectly got certificate for 'user3'"

## List certificate within expiration range ##

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-03-01:: -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration date::" user5 user6 user7
assertNotContainsUserCert "--expiration date::" user1 user2 user3 user4
assertNumberOfCerts 5

$FABRIC_CA_CLIENTEXEC certificate list --expiration ::2018-01-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration ::date" user1
assertNotContainsUserCert "--expiration ::date" user2
assertNumberOfCerts 1

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-01::2018-03-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration date1::date2" user2 user3 user4 user8
assertNotContainsUserCert "--expiration data1::date2" user1
assertNumberOfCerts 5

$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-01::2018-03-01 --id user3 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration date1::date2" user3
assertNotContainsUserCert "--expiration date1::date2" user2
assertNumberOfCerts 2

## List certificate within revocation range ##

$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-02-01:: -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation date::" user5
assertNumberOfCerts 1

$FABRIC_CA_CLIENTEXEC certificate list --revocation ::2018-01-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation ::date" user6
assertNotContainsUserCert "--revocation ::date" user5
assertNumberOfCerts 1

$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-01-01::2018-02-01 -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation date1::date2" user7
assertNotContainsUserCert "--revocation data1::date2" user5 user6
assertNumberOfCerts 2

## List certificates within expiration range but have not been revoked ##
$FABRIC_CA_CLIENTEXEC certificate list --expiration 2018-01-20::2018-01-30 --notrevoked -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--expiration --notrevoekd" user4
assertNotContainsUserCert "--expiration --notrevoked" user8
assertNumberOfCerts 1

## List certificates within revocation range but have not expired ##
$FABRIC_CA_CLIENTEXEC certificate list --revocation 2018-01-01::2018-01-30 --notexpired -H $CA_CFG_PATH/$USERNAME > output.txt
assertContainsUserCert "--revocation --notexpired" user7
assertNotContainsUserCert "--revocation --notexpired" user8
assertNumberOfCerts 1

$SCRIPTDIR/fabric-ca_setup.sh -K
mysqlDBCleanup

#####################################################################
# Testing Certificates API with MySQL - Complete
#####################################################################

rm server.txt
rm output.txt
rm cert.pem
rm key.pem
