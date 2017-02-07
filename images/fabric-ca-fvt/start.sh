#!/bin/bash
su postgres -c '/usr/lib/postgresql/9.5/bin/postgres -D /usr/local/pgsql/data' &
timeout=10
i=0
while ! nc -zvnt -w 5 127.0.0.1 5432; do
 sleep 1
 if test $i -gt $timeout; then break; fi;
 let i++;
done

/usr/bin/mysqld_safe &
i=0
while ! nc -zvnt -w 5 127.0.0.1 3306; do
 sleep 1
 if test $i -gt $timeout; then break; fi;
 let i++;
done

exec "$@"
