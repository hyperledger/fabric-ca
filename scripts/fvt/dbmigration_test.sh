#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

TESTCASE="db_migration"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0
DBNAME="fabric_ca"

TESTDIR="/tmp/$TESTCASE"
export FABRIC_CA_CLIENT_HOME="/tmp/db_migration/admin"
export FABRIC_CA_SERVER_HOME="$TESTDIR"
export CA_CFG_PATH="$TESTDIR"

###### MYSQL ######

$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d mysql # Start up the server and the new schema should get created
$SCRIPTDIR/fabric-ca_setup.sh -K # Kill the server
$SCRIPTDIR/fabric-ca_setup.sh -S -X -D -d mysql # Start up the server again and it should try to update the schema again, should result in no errors
if test $? -ne 0; then
    ErrorMsg "Failed to start up server that is using the latest database schema"
fi
$SCRIPTDIR/fabric-ca_setup.sh -K # Kill the server

# Create the database tables using the old schema
echo "Creating '$DBNAME' MySQL database and tables before starting up server"
mysql --host=localhost --user=root --password=mysql -e "drop database $DBNAME;"
mysql --host=localhost --user=root --password=mysql -e "create database $DBNAME;"
mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "CREATE TABLE users (id VARCHAR(64) NOT NULL, token blob, type VARCHAR(64), affiliation VARCHAR(64), attributes VARCHAR(256), state INTEGER, max_enrollments INTEGER, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin;"
mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "CREATE TABLE affiliations (name VARCHAR(64) NOT NULL UNIQUE, prekey VARCHAR(64));"
mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "CREATE TABLE certificates (id VARCHAR(64), serial_number varbinary(128) NOT NULL, authority_key_identifier varbinary(128) NOT NULL, ca_label varbinary(128), status varbinary(128) NOT NULL, reason int, expiry timestamp DEFAULT 0, revoked_at timestamp DEFAULT 0, pem varbinary(4096) NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier)) DEFAULT CHARSET=utf8 COLLATE utf8_bin;"
mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT character_maximum_length FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'id';" | grep "64"
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 64"
fi

# Start up the server and the schema should get updated
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d mysql

enroll
if test $? -ne 0; then
    ErrorMsg "Failed to enroll $REGISTRAR"
fi

# Register a user with a username of 128 character. This should pass with the updated schema
USERNAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 128 | head -n 1)
register "" $USERNAME
if test $? -ne 0; then
    ErrorMsg "Failed to register $USERNAME"
fi

# Register a user with a username of 300 character. This should result in an error
USERNAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 300 | head -n 1)
register "" $USERNAME
if test $? -ne 1; then
    ErrorMsg "Should have failed to register $USERNAME"
fi

$SCRIPTDIR/fabric-ca_setup.sh -K

# Check that the new schema took affect
mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT column_name, character_maximum_length FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users';" > $TESTDIR/text.txt
grep 'id'$'\t''255' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi
grep 'type'$'\t''256' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 256"
fi
grep 'affiliation'$'\t''256' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 256"
fi
grep 'attributes'$'\t''65535' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'attributes' should have character limit of 65535"
fi

mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT column_name, character_maximum_length FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'affiliations';" > $TESTDIR/text.txt
grep 'name'$'\t''1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'name' should have character limit of 1024"
fi
grep 'prekey'$'\t''1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'prekey' should have character limit of 1024"
fi

mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT column_name, character_maximum_length FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'certificates' AND COLUMN_NAME = 'id';" | grep "255"
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi

###### POSTGRES ######
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d postgres # Start up the server and the new schema should get created
$SCRIPTDIR/fabric-ca_setup.sh -K # Kill the server
$SCRIPTDIR/fabric-ca_setup.sh -S -X -D -d postgres # Start up the server again and it should try to update the schema again, should result in no errors
if test $? -ne 0; then
    ErrorMsg "Failed to start up server that is using the latest database schema"
fi
$SCRIPTDIR/fabric-ca_setup.sh -K # Kill the server


# Create the database tables using the old schema
echo "Creating '$DBNAME' Postgres database and tables before starting up server"
psql -c "drop database $DBNAME"
psql -c "create database $DBNAME"
psql -d $DBNAME -c "CREATE TABLE users (id VARCHAR(64), token bytea, type VARCHAR(64), affiliation VARCHAR(64), attributes VARCHAR(256), state INTEGER,  max_enrollments INTEGER)"
psql -d $DBNAME -c "CREATE TABLE affiliations (name VARCHAR(64) NOT NULL UNIQUE, prekey VARCHAR(64))"
psql -d $DBNAME -c "CREATE TABLE certificates (id VARCHAR(64), serial_number bytea NOT NULL, authority_key_identifier bytea NOT NULL, ca_label bytea, status bytea NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem bytea NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier))"
psql -d $DBNAME -c "SELECT character_maximum_length FROM information_schema.columns where table_name = 'users' AND column_name = 'id';" | grep "64"
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 64"
fi

# Start up the server and the schema should get updated
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d postgres

enroll
if test $? -ne 0; then
    ErrorMsg "Failed to enroll $REGISTRAR"
fi

# Register a user with a username of 128 character. This should pass with the updated schema
USERNAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 128 | head -n 1)
register "" $USERNAME
if test $? -ne 0; then
    ErrorMsg "Failed to register $USERNAME"
fi

# Register a user with a username of 300 character. This should result in an error
USERNAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 300 | head -n 1)
register "" $USERNAME
if test $? -ne 1; then
    ErrorMsg "Should have failed to register $USERNAME"
fi

$SCRIPTDIR/fabric-ca_setup.sh -K

# Check that the new schema took affect
psql -d $DBNAME -c "SELECT column_name, character_maximum_length FROM information_schema.columns where table_name = 'users';" > $TESTDIR/text.txt
grep 'id              |                      255' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi
grep 'type            |                      256' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 256"
fi
grep 'affiliation     |                      256' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 256"
fi
psql -d $DBNAME -c "SELECT data_type FROM information_schema.columns where table_name = 'users' AND column_name = 'attributes';" | grep "text"
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should be type 'text'"
fi

psql -d $DBNAME -c "SELECT column_name, character_maximum_length FROM information_schema.columns where table_name = 'affiliations';" > $TESTDIR/text.txt
grep 'name        |                     1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'name' should have character limit of 1024"
fi
grep 'prekey      |                     1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'prekey' should have character limit of 1024"
fi

psql -d $DBNAME -c "SELECT column_name, character_maximum_length FROM information_schema.columns where table_name = 'certificates' AND column_name = 'id';" | grep "255"
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi

CleanUp $RC
exit $RC