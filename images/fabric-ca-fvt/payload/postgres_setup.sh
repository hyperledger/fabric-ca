#!/bin/bash
RC=0

# Configure and start postgres
echo $PGUSER:$PGUSER | chpasswd
mkdir -p $PGDATA && chown postgres:postgres $PGDATA
su $PGUSER -c "/usr/lib/postgresql/$PGVER/bin/initdb -D $PGDATA"
su $PGUSER -c "/usr/lib/postgresql/$PGVER/bin/pg_ctl start -D $PGDATA" &&\
                   sleep 10 &&\
                   psql -U postgres -h localhost -c "ALTER USER $PGUSER WITH PASSWORD '$PGPASSWORD';" &&\
                   su postgres -c "/usr/lib/postgresql/$PGVER/bin/pg_ctl stop"
let RC+=$?
echo "host all  all    0.0.0.0/0  trust" >> ${PGDATA}/pg_hba.conf
echo "listen_addresses='*'" >> ${PGDATA}/postgresql.conf
# Enable TLS for postgres
cp $FABRIC_CA_DATA/$TLS_BUNDLE $PGDATA || let RC+=1
cp $FABRIC_CA_DATA/$TLS_SERVER_CERT $PGDATA || let RC+=1
cp $FABRIC_CA_DATA/$TLS_SERVER_KEY  $PGDATA || let RC+=1
# postgres insists on restricted access to keys
chown $PGUSER.$PGUSER $PGDATA/*pem || let RC+=1
chmod 600 $PGDATA/FabricTlsServer*.pem || let RC+=1
sed -i "s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl[[:blank:]]*=[[:blank:]]*\).*/\1\2on/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl_cert_file[[:blank:]]*=[[:blank:]]*\).*/\1\2'$TLS_SERVER_CERT'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl_key_file[[:blank:]]*=[[:blank:]]*\).*/\1\2'$TLS_SERVER_KEY'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl_ca_file[[:blank:]]*=[[:blank:]]*\).*/\1\2'$TLS_BUNDLE'/" $PGDATA/postgresql.conf || let RC+=1

# Generate version-agnostic postgres command
ln -s /usr/lib/postgresql/$PGVER/bin/postgres /usr/local/bin/postgres && chmod 777 /usr/local/bin/postgres || let RC+=1

exit $RC
