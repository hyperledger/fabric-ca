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

###### SQLITE #####

mkdir -p $FABRIC_CA_SERVER_HOME
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'CREATE TABLE IF NOT EXISTS users (id VARCHAR(64), token bytea, type VARCHAR(64), affiliation VARCHAR(64), attributes TEXT, state INTEGER,  max_enrollments INTEGER);'
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'CREATE TABLE IF NOT EXISTS affiliations (name VARCHAR(64) NOT NULL UNIQUE, prekey VARCHAR(64));'
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'CREATE TABLE IF NOT EXISTS certificates (id VARCHAR(64), serial_number blob NOT NULL, authority_key_identifier blob NOT NULL, ca_label blob, status blob NOT NULL, reason int, expiry timestamp, revoked_at timestamp, pem blob NOT NULL, PRIMARY KEY(serial_number, authority_key_identifier));'
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "INSERT INTO affiliations (name) VALUES ('org1');"
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "INSERT INTO affiliations (name) VALUES ('org1.dep1');"
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "INSERT INTO certificates (id, serial_number, authority_key_identifier) VALUES ('registrar', '1234', '12345');"

# Start up the server and the schema should get updated
$SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d sqlite3

enroll
if test $? -ne 0; then
    ErrorMsg "Failed to enroll $REGISTRAR"
fi

$SCRIPTDIR/fabric-ca_setup.sh -K # Kill the server

# Check that the new schema took affect
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'pragma table_info(users)' > $TESTDIR/output.txt
grep 'id|VARCHAR(255)' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi
grep 'type|VARCHAR(256)' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'type' should have character limit of 256"
fi
grep 'affiliation|VARCHAR(1024)' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 1024"
fi
grep 'attributes|TEXT' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'attributes' should be a TEXT field"
fi
grep 'level|INTEGER' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'level' should be a INTEGER field"
fi
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'SELECT value FROM properties WHERE (property = "identity.level")' | grep '2'
if [ $? != 0 ]; then
    ErrorMsg "Incorrect level found for 'identity.level' in properties table"
fi
grep 'incorrect_password_attempts|INTEGER' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'incorrect_password_attempts' should be a INTEGER field"
fi

sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'pragma table_info(affiliations)' > $TESTDIR/output.txt
grep 'name|VARCHAR(1024)' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'name' should have character limit of 1024"
fi
grep 'prekey|VARCHAR(1024)' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'prekey' should have character limit of 1024"
fi
grep 'level|INTEGER' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'level' should be a INTEGER field"
fi
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'SELECT value FROM properties WHERE (property = "affiliation.level")' | grep '1'
if [ $? != 0 ]; then
    ErrorMsg "Incorrect level found for 'affiliation.level' in properties table"
fi


sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'pragma table_info(certificates)' > $TESTDIR/output.txt
grep 'id|VARCHAR(255)' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi
grep 'level|INTEGER' $TESTDIR/output.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'level' should be a INTEGER field"
fi
sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'SELECT value FROM properties WHERE (property = "certificate.level")' | grep '1'
if [ $? != 0 ]; then
    ErrorMsg "Incorrect level found for 'certificate.level' in properties table"
fi

rm $FABRIC_CA_SERVER_HOME/$DBNAME

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
grep 'affiliation'$'\t''1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 1024"
fi
grep 'attributes'$'\t''65535' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'attributes' should have character limit of 65535"
fi
grep 'incorrect_password_attempts' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Failed to create column 'incorrect_password_attempts' in MySQL"
fi

mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT column_name, character_maximum_length, data_type, extra FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'affiliations';" > $TESTDIR/text.txt
grep 'id'$'\t''NULL'$'\t''int'$'\t''auto_increment' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Integer auto_increment column 'id' should be present in the affiliations table"
fi
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
grep -E 'id|255' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi
grep -E 'type|256' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 256"
fi
grep -E 'affiliation|1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should have character limit of 1024"
fi
psql -d $DBNAME -c "SELECT data_type FROM information_schema.columns where table_name = 'users' AND column_name = 'attributes';" | grep "text"
if [ $? != 0 ]; then
    ErrorMsg "Database column 'affiliation' should be type 'text'"
fi
grep 'incorrect_password_attempts' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'incorrect_passwords_attempts' failed to be created"
fi

psql -d $DBNAME -c "SELECT column_name, character_maximum_length FROM information_schema.columns where table_name = 'affiliations';" > $TESTDIR/text.txt
grep -E 'name|1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'name' should have character limit of 1024"
fi
grep -E 'prekey|1024' $TESTDIR/text.txt
if [ $? != 0 ]; then
    ErrorMsg "Database column 'prekey' should have character limit of 1024"
fi

psql -d $DBNAME -c "SELECT column_name, character_maximum_length FROM information_schema.columns where table_name = 'certificates' AND column_name = 'id';" | grep "255"
if [ $? != 0 ]; then
    ErrorMsg "Database column 'id' should have character limit of 255"
fi

CleanUp $RC
exit $RC
