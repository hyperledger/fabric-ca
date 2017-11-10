#!/bin/bash
RC=0
arch=$(uname -m)

mkdir -p /var/run/mysqld
chown mysql:mysql /var/run/mysqld

# Mysql certificates
cp $FABRIC_CA_DATA/$TLS_BUNDLE $MYSQLDATA/
cp $FABRIC_CA_DATA/$TLS_SERVER_CERT $MYSQLDATA/
openssl rsa -in $FABRIC_CA_DATA/$TLS_SERVER_KEY -out $MYSQLDATA/$TLS_SERVER_KEY || let RC+=1
chown mysql.mysql $MYSQLDATA/*pem
chmod 600 $MYSQLDATA/$TLS_SERVER_KEY
test $arch = s390x && MYCNF=/etc/mysql/my.cnf || MYCNF=/etc/mysql/mysql.conf.d/mysqld.cnf
sed -i "s/^[[:blank:]]*#*[[:blank:]]*ssl-ca=.*/ssl-ca=$TLS_BUNDLE/;
        s/\(^[[:blank:]]*\)#*\([[:blank:]]*max_connections[[:blank:]]*=[[:blank:]]*\).*/\1\22000/;
        s/^[[:blank:]]*#*[[:blank:]]*ssl-cert=.*/ssl-cert=$TLS_SERVER_CERT/;
        s/^[[:blank:]]*#*[[:blank:]]*ssl-key=.*/ssl-key=$TLS_SERVER_KEY/" $MYCNF || let RC+=1
chown -R mysql.mysql $MYSQLDATA
exit $RC
