#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE:="db_resiliency"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
TESTDATA="$FABRIC_CA/testdata"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
HOST="http://localhost:$PROXY_PORT"
RC=0

export FABRIC_CA_SERVER_HOME="/tmp/$TESTCASE"
export CA_CFG_PATH="/tmp/$TESTCASE"

MYSQLSERVERCONFIG="$FABRIC_CA_SERVER_HOME/mysqlserverconfig.yaml"
MYSQLSERVERCONFIG2="$FABRIC_CA_SERVER_HOME/mysqlserverconfig2.yaml"
PGSQLSERVERCONFIG="$FABRIC_CA_SERVER_HOME/pgsqlserverconfig.yaml"
PGSQLSERVERCONFIG2="$FABRIC_CA_SERVER_HOME/pgsqlserverconfig2.yaml"
MSP="$FABRIC_CA_SERVER_HOME/msp"
SERVERCERT="$FABRIC_CA_SERVER_HOME/fabric-ca-cert.pem"
DBNAME="fabric_ca"

function cleanup {
    rm $SERVERCERT
    rm -rf $MSP
    rm $SERVERLOG
}

function existingIdentity {
    grep "Identity '$1' already registered, loaded identity" $2 &> /dev/null
    if [ $? != 0 ]; then
        ErrorMsg "Should have thrown an error inserting an already registered user"
    else
        echo -e "\t Test - Already registered identity message encountered: passed"
    fi
}

function checkIdentity {
    grep "Successfully added identity $1 to the database" $2 &> /dev/null
    if [ $? != 0 ]; then
        ErrorMsg "Identity should not already exist in database, and should have gotten added"
    else
        echo -e "\t Test - New identity added: passed"
    fi
}

function existingAff {
    grep "Affiliation '$1' already exists" $2 &> /dev/null
    if [ $? != 0 ]; then
        ErrorMsg "Should have thrown an error inserting an already existing affiliation"
    else
        echo -e "\t Test - Already existing affiliation message encountered: passed"
    fi
}

function checkAff {
    grep "Affiliation '$1' added" $2 &> /dev/null
    if [ $? != 0 ]; then
        ErrorMsg "Affiliation should not already exist in database, and should have gotten added"
    else
        echo -e "\t Test - New affiliation added: passed"
    fi
}

function genConfig {
   mkdir -p $FABRIC_CA_SERVER_HOME
   # Create base configuration using mysql
   cat > $MYSQLSERVERCONFIG <<EOF
debug: true

db:
  type: mysql
  datasource: root:mysql@tcp(localhost:$MYSQL_PORT)/fabric_ca

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

   # mysql configuration with two bootstrap users
   cp $MYSQLSERVERCONFIG $MYSQLSERVERCONFIG2
   sed -i '/hf.IntermediateCA:/a\
     - name: c\
       pass: d\
       type: client\
       affiliation: ""\
       maxenrollments: -1\
       attrs:\
          hf.Registrar.Roles: "client,user,peer,validator,auditor"\
          hf.Registrar.DelegateRoles: "client,user,validator,auditor"\
          hf.Revoker: true\
          hf.IntermediateCA: true ' $MYSQLSERVERCONFIG2
   echo -e "   org3:\n      - department1" >> $MYSQLSERVERCONFIG2

   # Clone the mysql configuration for postgres
   cp $MYSQLSERVERCONFIG $PGSQLSERVERCONFIG
   cp $MYSQLSERVERCONFIG2 $PGSQLSERVERCONFIG2
   sed -i "s/type: mysql/type: postgres/
          s/datasource:.*/datasource: host=localhost port=$POSTGRES_PORT user=postgres password=postgres dbname=fabric_ca/" \
   $PGSQLSERVERCONFIG $PGSQLSERVERCONFIG2
}

$SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_SERVER_HOME
genConfig

# MySQL Test
echo "############################ MySQL Test ############################"

# Test scenario where database and tables exist, plus an already bootstrapped user is present in the users table
# Fabric-ca should bootstap a newly added identity to the config to the user table
echo "############## Test 1 ##############"
echo "Test1: Database and tables exist, plus an already bootstrapped user is present in the users table"
echo "Test1: Fabric-ca should bootstap a newly added identity to the config to the user table"
echo "Creating '$DBNAME' MySQL database and tables before starting up server"
mysql --host=localhost --user=root --password=mysql -e "drop database $DBNAME;" -e "create database $DBNAME;" &> /dev/null
mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "CREATE TABLE users (id VARCHAR(64) NOT NULL, token blob, type VARCHAR(64), affiliation VARCHAR(64), attributes VARCHAR(256), state INTEGER, max_enrollments INTEGER, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin;"  &> /dev/null

# Starting server first time with one bootstrap user
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test1a.txt"
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $MYSQLSERVERCONFIG 2>&1 | tee $SERVERLOG &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid && rm $SERVERLOG || ErrorExit "Failed to stop CA"
# Starting server second time with a second bootstrap user
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $MYSQLSERVERCONFIG2 2>&1 | tee $SERVERLOG &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid || ErrorExit "Failed to stop CA"

existingIdentity "a" $SERVERLOG # Check to see that appropriate error message was seen for an already registered user
checkIdentity "c" $SERVERLOG # Check to see that a new identity properly got registered
existingAff "org1" $SERVERLOG
checkAff "org3.department1" $SERVERLOG

# Test scenario where database exists but tables do not exist
# Fabric-ca should create the tables and bootstrap
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test2a.txt"
echo "############## Test 2 ##############"
echo "Test2: Database exist but tables do not exist"
echo "Test2: Fabric-ca should create the tables and bootstrap"
echo "Dropping and creating an empty '$DBNAME' database"
mysql --host=localhost --user=root --password=mysql -e "drop database fabric_ca;" -e "create database fabric_ca;" &> /dev/null

$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $MYSQLSERVERCONFIG2 2>&1 | tee $SERVERLOG &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid || ErrorExit "Failed to stop CA"
checkIdentity "a" $SERVERLOG # Check to see that a new identity properly got registered
checkIdentity "c" $SERVERLOG # Check to see that a new identity properly got registered

# Test scenario where database does not exist
# Fabric-ca should create the database and tables, and bootstrap
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test3a.txt"
echo "############## Test 3 ##############"
echo "Test3: Database does not exist"
echo "Test3: Fabric-ca should create the database and tables, and bootstrap"
echo "Dropping '$DBNAME' database"
mysql --host=localhost --user=root --password=mysql -e "drop database fabric_ca;" &> /dev/null

$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $MYSQLSERVERCONFIG2 2>&1 | tee $SERVERLOG &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid || ErrorExit "Failed to stop CA"

checkIdentity "a" $SERVERLOG # Check to see that a new identity properly got registered
checkIdentity "c" $SERVERLOG # Check to see that a new identity properly got registered

cleanup
# PostgreSQL Test
echo "############################ PostgresSQL Test ############################"

# Test scenario where database and tables exist, plus an already bootstrapped user is present in the users table
# Fabric-ca should create the tables and bootstrap
echo "############## Test 1 ##############"
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test1b.txt"
echo "Test1: Database and tables exist, plus an already bootstrapped user is present in the users table"
echo "Test1: Fabric-ca should bootstap a newly added identity to the config to the user table"
psql -c "drop database $DBNAME"
psql -c "create database $DBNAME"
psql -d fabric_ca -c "CREATE TABLE users (id VARCHAR(64), token bytea, type VARCHAR(64), affiliation VARCHAR(64), attributes VARCHAR(256), state INTEGER,  max_enrollments INTEGER)"

# Starting server first time with one bootstrap user
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $PGSQLSERVERCONFIG 2>&1 | tee $SERVERLOG &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid && rm $SERVERLOG || ErrorExit "Failed to stop CA"

# Starting server second time with a second bootstrap user
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $PGSQLSERVERCONFIG2 2>&1 | tee $SERVERLOG &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid || ErrorExit "Failed to stop CA"

existingIdentity "a" $SERVERLOG # Check to see that appropriate error message was seen for an already registered user
checkIdentity "c" $SERVERLOG # Check to see that a new identity properly got registered

existingAff "org1" $SERVERLOG
checkAff "org3.department1" $SERVERLOG

# Test scenario where database exist but tables do not exist
# Fabric-ca should create the tables and bootstrap
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test2b.txt"
echo "############## Test 2 ##############"
echo "Test2: Database exist but tables do not exist"
echo "Test2: Fabric-ca should create the tables and bootstrap"
psql -c "drop database $DBNAME"
psql -c "create database $DBNAME"

$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $PGSQLSERVERCONFIG2 2>&1 | tee $SERVERLOG &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid || ErrorExit "Failed to stop CA"

checkIdentity "a" $SERVERLOG # Check to see that a new identity properly got registered
checkIdentity "c" $SERVERLOG # Check to see that a new identity properly got registered

# Test scenario where database does not exist
# Fabric-ca should create the database and tables, and bootstrap
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test3b.txt"
echo "############## Test 3 ##############"
echo "Test3: Database does not exist"
echo "Test3: Fabric-ca should create the database and tables, and bootstrap"
psql -c "drop database $DBNAME"

$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $PGSQLSERVERCONFIG2 2>&1 | tee $SERVERLOG &
sleep 6 # Need to allow for Postgres to complete database and table creation
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"
pid=$(pidof fabric-ca-server)
killserver $pid || ErrorExit "Failed to stop CA"

checkIdentity "a" $SERVERLOG # Check to see that a new identity properly got registered
checkIdentity "c" $SERVERLOG # Check to see that a new identity properly got registered

echo "############################ PostgresSQL Test with Client ############################"

kill -INT `head -1 /usr/local/pgsql/data/postmaster.pid` # Shutdown postgres server
pollPostgres "" "" "" stop 2>&1 # Wait for postgres to stop

# Start fabric-ca server connecting to postgres, this will fail
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test1c.txt"
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $PGSQLSERVERCONFIG2 | tee $SERVERLOG 2>&1 &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"

# Enroll with a server that does not have a DB initialized, should expect to get back error
enroll a b 2>&1 | grep "Failed to connect to Postgres database"
if [ $? != 0 ]; then
    ErrorMsg "Enroll request should have failed due to uninitialized postgres database"
fi

# Start postgres server
su postgres -c 'postgres -D /usr/local/pgsql/data' &
pollPostgres # Wait for postgres to start
sleep 5 # Postgres port is available but sometimes get back 'pq: the database system is starting up' error. Putting in sleep to allow for start up to complete

# Enroll again, this time the server should try to reinitialize the DB before processing enroll request and this should succeed
enroll a b 2>&1 | grep "Stored client certificate"
if [ $? != 0 ]; then
    ErrorMsg "Enroll request should have passed"
fi

$SCRIPTDIR/fabric-ca_setup.sh -K

echo "############################ MySQL Test with Client ############################"

/etc/init.d/mysql stop >/dev/null 2>&1
pollMySql "" "" "" stop # Wait for MySQL to stop

# Start fabric-ca server connecting to MySQL, this will fail
SERVERLOG="$FABRIC_CA_SERVER_HOME/serverlog.test2c.txt"
$SCRIPTDIR/fabric-ca_setup.sh -S -X -g $MYSQLSERVERCONFIG2 | tee $SERVERLOG 2>&1 &
pollLogForMsg "Listening on https*://0.0.0.0:$CA_DEFAULT_PORT" $SERVERLOG || ErrorExit "Failed to log CA startup message"

# Enroll with a server that does not have a DB initialized, should expect to get back error
enroll a b 2>&1 | grep "Failed to connect to MySQL database"
if [ $? != 0 ]; then
    ErrorMsg "Enroll request should have failed due to uninitialized mysql database"
fi

# Start mysql server
/usr/bin/mysqld_safe --sql-mode=STRICT_TRANS_TABLES &
pollMySql # Wait for MySQL to start

# Enroll again, this time the server should try to reinitialize the DB before processing enroll request and this should succeed
enroll a b 2>&1 | grep "Stored client certificate"
if [ $? != 0 ]; then
    ErrorMsg "Enroll request should have passed"
fi

$SCRIPTDIR/fabric-ca_setup.sh -R -x $FABRIC_CA_SERVER_HOME

CleanUp $RC
exit $RC
