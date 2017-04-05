#!/bin/bash
POSTGRES_PORT=5432
MYSQL_PORT=3306
PORTS=($POSTGRES_PORT $MYSQL_PORT)

timeout=12
su postgres -c 'postgres -D /usr/local/pgsql/data' &
/usr/bin/mysqld_safe --sql-mode=STRICT_TRANS_TABLES &

for port in ${PORTS[*]}; do
   i=0
   while ! nc -zvnt -w 5 127.0.0.1 $port; do
      sleep 1
      if test $i -gt $timeout; then break; fi;
      let i++;
   done
done

exec "$@"
