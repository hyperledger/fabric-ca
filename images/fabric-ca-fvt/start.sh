#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

POSTGRES_PORT=5432
MYSQL_PORT=3306
MYSQL_VERSION=`mysqld --version|awk '{print $3}'`
LDAP_PORT=389
PORTS=($POSTGRES_PORT $MYSQL_PORT $LDAP_PORT)

timeout=12
su postgres -c 'postgres -D /usr/local/pgsql/data' &
# we need to check the version of mysql as behavior has changed with 5.7.19+
if [[ $MYSQL_VERSION == 5.7* ]] ;
then
  echo "detected mysql version ${MYSQL_VERSION}"
  rm -rf /var/lib/mysql && mkdir -p /var/lib/mysql /var/run/mysqld \
    && chown -R mysql:mysql /var/lib/mysql /var/run/mysqld \
    && chmod 777 /var/run/mysqld
  mysqld --initialize-insecure
fi

/usr/bin/mysqld_safe --sql-mode=STRICT_TRANS_TABLES &
/etc/init.d/slapd start &

for port in ${PORTS[*]}; do
   i=0
   while ! nc -zvnt -w 5 127.0.0.1 $port; do
      sleep 1
      test $i -gt $timeout && break
      let i++;
   done
done

if [[ $MYSQL_VERSION == 5.7* ]] ;
then
  # Set mysql root password
  sleep 3
  mysqladmin -u root password mysql
fi

exec "$@"
