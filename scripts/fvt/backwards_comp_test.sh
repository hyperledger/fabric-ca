#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

TESTCASE="backwards_comp"
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
RC=0

export FABRIC_CA_SERVER_HOME="/tmp/$TESTCASE"
export CA_CFG_PATH="/tmp/$TESTCASE"

TESTCONFIG="$FABRIC_CA_SERVER_HOME/testconfig.yaml"
DBNAME=fabric_ca

function genConfig {
  local version=$1
  : ${version:=""}

   mkdir -p $FABRIC_CA_SERVER_HOME
   # Create base configuration using mysql
   cat > $TESTCONFIG <<EOF
debug: true

db:
  type: mysql
  datasource: root:mysql@tcp(localhost:$MYSQL_PORT)/$DBNAME

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

  if [ "$version" != "" ]; then
    sed -i "1s/^/version: \"$version\"\n/" $TESTCONFIG
  fi

  if [[ $driver = "sqlite3" ]]; then
    sed -i "s/type: mysql/type: sqlite3/
        s/datasource:.*/datasource: $DBNAME/" $TESTCONFIG
  fi

  if [[ $driver = "postgres" ]]; then
    sed -i "s/type: mysql/type: postgres/
        s/datasource:.*/datasource: host=localhost port=$POSTGRES_PORT user=postgres password=postgres dbname=$DBNAME/" $TESTCONFIG
  fi

}

function resetDB {
  case "$driver" in
    sqlite3)
      rm -rf $FABRIC_CA_SERVER_HOME/$DBNAME ;;
    postgres)
      psql -d postgres -c "DROP DATABASE $DBNAME" ;;
    mysql)
      mysql --host=localhost --user=root --password=mysql -e "DROP DATABASE $DBNAME" ;;
    *)
      echo "Invalid database type"
      exit 1
      ;;
  esac
}

function createDB {
  case "$driver" in
    sqlite3)
      mkdir -p $FABRIC_CA_SERVER_HOME ;;
    postgres)
      psql -d postgres -c "CREATE DATABASE $DBNAME" ;;
    mysql)
      mysql --host=localhost --user=root --password=mysql -e "CREATE DATABASE $DBNAME" ;;
    *)
      echo "Invalid database type"
      exit 1
      ;;
  esac
}

# loadUsers creates table using old schema and populates the users table with users
function loadUsers {
  case "$driver" in
    sqlite3)
      mkdir -p $FABRIC_CA_SERVER_HOME
      sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME 'CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER);'
      sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
    VALUES ('registrar', '', 'user', 'org2', '[{\"name\": \"hf.Registrar.Roles\", \"value\": \"user,peer,client\"},{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1');"
      sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments)
    VALUES ('notregistrar', '', 'user', 'org2', '[{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1');"

      sed -i "s/type: mysql/type: sqlite3/
          s/datasource:.*/datasource: $DBNAME/" $TESTCONFIG
      ;;
    postgres)
      psql -d postgres -c "CREATE DATABASE $DBNAME"
      psql -d $DBNAME -c "CREATE TABLE IF NOT EXISTS users (id VARCHAR(255), token bytea, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER,  max_enrollments INTEGER)"
      psql -d $DBNAME -c "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments) VALUES ('registrar', '', 'user', 'org2', '[{\"name\": \"hf.Registrar.Roles\", \"value\": \"user,peer,client\"},{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"
      psql -d $DBNAME -c "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments) VALUES ('notregistrar', '', 'user', 'org2', '[{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"

      sed -i "s/type: mysql/type: postgres/
          s/datasource:.*/datasource: host=localhost port=$POSTGRES_PORT user=postgres password=postgres dbname=$DBNAME $postgresTls/" $TESTCONFIG
      ;;
    mysql)
      mysql --host=localhost --user=root --password=mysql -e "CREATE DATABASE $DBNAME"
      mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) NOT NULL, token blob, type VARCHAR(256), affiliation VARCHAR(1024), attributes TEXT, state INTEGER, max_enrollments INTEGER, PRIMARY KEY (id)) DEFAULT CHARSET=utf8 COLLATE utf8_bin"
      mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments) VALUES ('registrar', '', 'user', 'org2', '[{\"name\": \"hf.Registrar.Roles\", \"value\": \"user,peer,client\"},{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"
      mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "INSERT INTO users (id, token, type, affiliation, attributes, state, max_enrollments) VALUES ('notregistrar', '', 'user', 'org2', '[{\"name\": \"hf.Revoker\", \"value\": \"true\"}]', '0', '-1')"
      ;;
    *)
      echo "Invalid database type"
      exit 1
      ;;
  esac
}

function validateUsers {
  local result=$1
  : ${result:= 0}
  case "$driver" in
    sqlite3)
      sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "SELECT attributes FROM users WHERE (id = 'registrar');" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq 1; then
        ErrorMsg "Failed to correctly migrate user 'registar' on sqlite"
      fi
      sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "SELECT attributes FROM users WHERE (id = 'notregistrar');" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq 0; then
        ErrorMsg "Failed to correctly migrate user 'notregistar' on sqlite"
      fi
      sqlite3 $FABRIC_CA_SERVER_HOME/$DBNAME "SELECT attributes FROM users WHERE (id = 'a');" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq $result; then
        ErrorMsg "Failed to correctly migrate user 'a' on sqlite"
      fi
      ;;
    postgres)
      psql -d $DBNAME -c "SELECT attributes FROM users WHERE (id = 'registrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq 1; then
        ErrorMsg "Failed to correctly migrate user 'registrar' on postgres"
      fi
      psql -d $DBNAME -c "SELECT attributes FROM users WHERE (id = 'notregistrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq 0; then
        ErrorMsg "Failed to correctly migrate user 'notregistrar' on postgres"
      fi
      psql -d $DBNAME -c "SELECT attributes FROM users WHERE (id = 'a')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq $result; then
        ErrorMsg "Failed to correctly migrate user 'a' on postgres"
      fi
      ;;
    mysql)
      mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT attributes FROM users WHERE (id = 'registrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq 1; then
        ErrorMsg "Failed to correctly migrate user 'registrar' on mysql"
      fi
      mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT attributes FROM users WHERE (id = 'notregistrar')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq 0; then
        ErrorMsg "Failed to correctly migrate user 'notregistrar' on mysql"
      fi
      mysql --host=localhost --user=root --password=mysql --database=$DBNAME -e "SELECT attributes FROM users WHERE (id = 'a')" | grep '"name":"hf.Registrar.Attributes","value":"*"'
      if test $? -eq $result; then
        ErrorMsg "Failed to correctly migrate user 'a' on mysql"
      fi
      ;;
    *)
      echo "Invalid database type"
      exit 1
      ;;
  esac
}

# Starting server with a configuration file that is a higher version than the server executable should fail
genConfig "9.9.9.9"
fabric-ca-server start -b a:b -c $TESTCONFIG -d
if test $? -ne 1; then
    ErrorMsg "Should have failed to start server, configuration file version is higher than the server executable version"
fi

# Test that the server should fail to initialize if the database level is higher than the server executable level
for driver in sqlite3 postgres mysql; do

   # Initializing a server with a database that has a higher level than the server executable
  resetDB
  createDB

  case "$driver" in
  sqlite3)
    rm -rf $FABRIC_CA_SERVER_HOME
    mkdir -p $FABRIC_CA_SERVER_HOME
    sqlite3 $FABRIC_CA_SERVER_HOME/fabric_ca 'CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property));'
    sqlite3 $FABRIC_CA_SERVER_HOME/fabric_ca 'INSERT INTO properties (property, value) Values ("identity.level", "9");'
    ;;
  postgres)
    psql -d postgres -c "DROP DATABASE fabric_ca"
    psql -d postgres -c "CREATE DATABASE fabric_ca"
    psql -d fabric_ca -c "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"
    psql -d fabric_ca -c "INSERT INTO properties (property, value) Values ('identity.level', '9')"
    ;;
  mysql)
    mysql --host=localhost --user=root --password=mysql -e "DROP DATABASE fabric_ca"
    mysql --host=localhost --user=root --password=mysql -e "CREATE DATABASE fabric_ca"
    mysql --host=localhost --user=root --password=mysql --database=fabric_ca -e "CREATE TABLE IF NOT EXISTS properties (property VARCHAR(255), value VARCHAR(256), PRIMARY KEY(property))"
    mysql --host=localhost --user=root --password=mysql --database=fabric_ca -e "INSERT INTO properties (property, value) Values ('identity.level', '9')"
    ;;
  *)
    echo "Invalid database type"
    exit 1
    ;;
  esac

  $SCRIPTDIR/fabric-ca_setup.sh -I -D -d $driver
  if test $? -eq 0; then
    ErrorMsg "Should have failed to initialize server because the database level is higher than the server"
  fi
  $SCRIPTDIR/fabric-ca_setup.sh -K

  resetDB

  # Starting server with latest level on the configuration file, all registrars currently
  # in database will be migrated and any new users defined in the configuration will be loaded as is
  # and will not have migration performed on them
  genConfig "1.1.0"
  loadUsers

  $SCRIPTDIR/fabric-ca_setup.sh -I -D -g $TESTCONFIG
  if test $? -eq 1; then
    ErrorMsg "Failed to start server, with the latest configuration file version"
  fi
  $SCRIPTDIR/fabric-ca_setup.sh -K

  validateUsers
  resetDB
done

CleanUp $RC
exit $RC
