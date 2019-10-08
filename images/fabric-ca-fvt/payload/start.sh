#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

POSTGRES_PORT=5432
MYSQL_PORT=3306
LDAP_PORT=389
PORTS=($LDAP_PORT)

timeout=30
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

i=0
while ! nc -zvt -w 5 "${MYSQLHOST}" $MYSQL_PORT; do
  sleep 1
  test $i -gt $timeout && break
  let i++
done

mysql -h ${MYSQLHOST} -u root --password=mysql -e "SET @@global.sql_mode=\"STRICT_TRANS_TABLES\""

exec "$@"
