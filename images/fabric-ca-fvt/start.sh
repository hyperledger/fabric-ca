#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

POSTGRES_PORT=5432
MYSQL_PORT=3306
LDAP_PORT=389
PORTS=($POSTGRES_PORT $MYSQL_PORT $LDAP_PORT)

timeout=12
service rsyslog start
su postgres -c 'postgres -D /usr/local/pgsql/data' &
chown -R mysql.mysql /var/lib/mysql
/usr/bin/mysqld_safe --sql-mode=STRICT_TRANS_TABLES &
# Set "olcIdleTimeout" to 1 second to force slapd (the LDAP server) to
# close connections after they have been idle for 1 second.  This is
# necessary to adequately validate that the fabric-ca-server correctly
# reconnects after the LDAP server has closed a connection.
# This is not the recommended configuration of slapd from a performance
# perspective.
echo "olcIdleTimeout: 1" >> "/etc/ldap/slapd.d/cn=config.ldif"
/etc/init.d/slapd start &

for port in ${PORTS[*]}; do
   i=0
   while ! nc -zvnt -w 5 127.0.0.1 $port; do
      sleep 1
      test $i -gt $timeout && break
      let i++;
   done
done

exec "$@"
