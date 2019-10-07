#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

POSTGRES_PORT=5432
MYSQL_PORT=3306
LDAP_PORT=389
PORTS=($POSTGRES_PORT $LDAP_PORT)

timeout=30
su postgres -c 'postgres -D /usr/local/pgsql/data' &
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
while ! nc -zvt -w 5 $MYSQL_HOST $MYSQL_PORT; do
  sleep 5
  test $i -gt $timeout && break
  let i++
done

mysql -h ${MYSQL_HOST} -u root --password=mysql -e "SET @@global.sql_mode=\"STRICT_TRANS_TABLES\";"

exec "$@"
