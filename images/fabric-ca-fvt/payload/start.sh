#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

POSTGRES_PORT=5432
MYSQL_PORT=3306
LDAP_PORT=389
PORTS=($MYSQL_PORT $LDAP_PORT)

timeout=30
chown -R mysql.mysql $MYSQLDATA
/usr/bin/mysqld_safe --sql-mode=STRICT_TRANS_TABLES &
/etc/init.d/slapd start &

for port in ${PORTS[*]}; do
  i=0
  while ! nc -zvnt -w 5 $HOSTADDR $port; do
    sleep 1
    test $i -gt $timeout && break
    let i++
  done
done

i=0
while ! nc -zvt -w 5 postgres $POSTGRES_PORT; do
  sleep 1
  test $i -gt $timeout && break
  let i++
done

exec "$@"
