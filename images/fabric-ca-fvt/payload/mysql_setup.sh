#!/bin/bash
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
RC=0

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install default-mysql-server -y

mkdir -p /var/run/mysqld
chown mysql:mysql /var/run/mysqld

# Mysql certificates
cp $FABRIC_CA_DATA/$TLS_BUNDLE $MYSQLDATA/
cp $FABRIC_CA_DATA/$TLS_SERVER_CERT $MYSQLDATA/
openssl rsa -in $FABRIC_CA_DATA/$TLS_SERVER_KEY -out $MYSQLDATA/$TLS_SERVER_KEY || let RC+=1
chown mysql:mysql $MYSQLDATA/*pem
chmod 600 $MYSQLDATA/$TLS_SERVER_KEY
MYCNF=/etc/mysql/mariadb.conf.d/50-server.cnf
sed -i "s/^[[:blank:]]*#*[[:blank:]]*ssl-ca=.*/ssl-ca=$TLS_BUNDLE/;
        s/\(^[[:blank:]]*\)#*\([[:blank:]]*max_connections[[:blank:]]*=[[:blank:]]*\).*/\1\22000/;
        s/^[[:blank:]]*#*[[:blank:]]*ssl-cert=.*/ssl-cert=$TLS_SERVER_CERT/;
        s/^[[:blank:]]*#*[[:blank:]]*ssl-key=.*/ssl-key=$TLS_SERVER_KEY/" $MYCNF || let RC+=1
chown -R mysql:mysql $MYSQLDATA

/usr/bin/mariadbd-safe --sql-mode=STRICT_TRANS_TABLES &
sleep 5
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('mysql')"

exit $RC
