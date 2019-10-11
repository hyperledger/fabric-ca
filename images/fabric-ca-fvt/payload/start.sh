#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

function testConnection() {
  timeout=5
  i=0
  while ! nc -zvt -w 5 "${1}" "${2}"; do
    sleep 5
    test $i -gt $timeout && break
    i=$((i + 1))
  done
}

/etc/init.d/slapd start &

testConnection mysql 3306  # Test MySQL container is ready
testConnection localhost 389        # Test LDAP is running
testConnection postgres 5432        # Test Postgres container is ready

mysql -h mysql -u root --password=mysql -e "SET @@global.sql_mode=\"STRICT_TRANS_TABLES\""

exec "$@"
