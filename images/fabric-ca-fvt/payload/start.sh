#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

/etc/init.d/slapd start &

function testConnection() {
  timeout=30
  i=0
  while ! nc -zt -w 5 "${1}" "${2}"; do
    sleep "${3}"
    test $i -gt $timeout && break
    i=$((i + ${3}))
  done
}

testConnection 127.0.0.1 389 1
testConnection postgres 5432 1
testConnection mysql 3306 5

mysql -h mysql -u root --password=mysql -e "SET @@GLOBAL.sql_mode=\"STRICT_TRANS_TABLES\""

exec "$@"
