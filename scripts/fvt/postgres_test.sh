#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

TESTCASE="postgres"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0

export FABRIC_CA_SERVER_HOME="/tmp/$TESTCASE"

PGSQLSERVERCONFIG="$FABRIC_CA_SERVER_HOME/pgsqlserverconfig.yaml"
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.txt"
MSP="$FABRIC_CA_SERVER_HOME/msp"
SERVERCERT="$FABRIC_CA_SERVER_HOME/fabric-ca-cert.pem"
DBNAME="fabric_ca"

function cleanup {
    rm $SERVERCERT
    rm -rf $MSP
    rm $SERVERLOG
}

function configureDB {
    psql -c "CREATE USER testuser WITH PASSWORD 'testuserpw' LOGIN"
    psql -c "CREATE DATABASE testdb"
    psql -d testdb -c "DROP DATABASE $DBNAME"
    psql -d testdb -c "DROP DATABASE postgres"
}

function resetDB {
    psql -d testdb -c "ALTER DATABASE template1_temp RENAME TO template1"
    psql -d testdb -c "CREATE DATABASE $DBNAME"
    psql -d testdb -c "CREATE DATABASE postgres"
    psql -d testdb -c "ALTER USER testuser WITH NOCREATEDB"
}

function genConfig {
   mkdir -p $FABRIC_CA_SERVER_HOME
   cat > $PGSQLSERVERCONFIG <<EOF
debug: true

db:
  type: postgres
  datasource: host=localhost port=$POSTGRES_PORT user=testuser password=testuserpw dbname=fabric_ca

tls:
  enabled: true
  certfile: $TLS_SERVERCERT
  keyfile: $TLS_SERVERKEY

registry:
  # Maximum number of times a password/secret can be reused for enrollment
  # (default: -1, which means there is no limit)
  maxenrollments: -1

  # Contains identity information which is used when LDAP is disabled
  identities:
     - name: a
       pass: b
       type: client
       affiliation: ""
       maxenrollments: -1
       attrs:
          hf.Registrar.Roles: "client,user,peer,validator,auditor"
          hf.Registrar.DelegateRoles: "client,user,validator,auditor"
          hf.Revoker: true
          hf.IntermediateCA: true

affiliations:
   org1:
      - department1
      - department2
   org2:
      - department1
EOF
}

genConfig
cleanup
configureDB

# TEST 1: Database user does not have permission to create DB and also
# no database exists with the same name as user
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $PGSQLSERVERCONFIG 2>&1 | tee $SERVERLOG &
pollFabricCa "" "" $CA_DEFAULT_PORT
$SCRIPTDIR/fabric-ca_setup.sh -K
grep "pq: permission denied to create database" $SERVERLOG &> /dev/null
if [ $? != 0 ]; then
    ErrorMsg "'testuser' should not have been able to create database, does not have permissions"
fi

# TEST 2: There are no database to establish a connection, an error is expected
# Three database are tried, the database specified in connection string, postgres,
# and template1
psql -d testdb -c "ALTER DATABASE template1 RENAME TO template1_temp"
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $PGSQLSERVERCONFIG 2>&1 | tee $SERVERLOG &
pollFabricCa "" "" $CA_DEFAULT_PORT
grep "Please create one of these database before continuing" $SERVERLOG &> /dev/null
if [ $? != 0 ]; then
    ErrorMsg "None of the database expected exist, should have thrown an error in the logs"
fi

# TEST 3: User has permissions to create DB and at least of the expected database
# exists, should successfully initialize database now
psql -d testdb -c "ALTER DATABASE template1_temp RENAME TO template1"
psql -d testdb -c "ALTER USER testuser WITH CREATEDB"

# Enroll should try to reinitialize the DB before processing enroll request and should succeed
enroll a b 2>&1 | grep "Stored client certificate"
if [ $? != 0 ]; then
    ErrorMsg "Enroll request should have passed"
fi

$SCRIPTDIR/fabric-ca_setup.sh -K
grep "Initialized postgres database" $SERVERLOG &> /dev/null
if [ $? != 0 ]; then
    ErrorMsg "Postgres database should have been successfully initialized"
fi

resetDB
CleanUp $RC
exit $RC
