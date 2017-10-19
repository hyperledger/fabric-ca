#!/bin/bash
RC=0

# Configure and start postgres
echo $PGUSER:$PGUSER | chpasswd
mkdir -p $PGDATA && chown $PGUSER:$PGUSER $PGDATA
su $PGUSER -c "/usr/lib/postgresql/$PGVER/bin/initdb -D $PGDATA"
su $PGUSER -c "/usr/lib/postgresql/$PGVER/bin/pg_ctl start -D $PGDATA" &&\
                   sleep 10 &&\
                   psql -U $PGUSER -h localhost -c "ALTER USER $PGUSER WITH PASSWORD '$PGPASSWORD';" &&\
                   su $PGUSER -c "/usr/lib/postgresql/$PGVER/bin/pg_ctl stop"
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
s/\(^[[:blank:]]*\)#*\([[:blank:]]*max_connections[[:blank:]]*=[[:blank:]]*\).*/\1\22000/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl_cert_file[[:blank:]]*=[[:blank:]]*\).*/\1\2'$TLS_SERVER_CERT'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl_cert_file[[:blank:]]*=[[:blank:]]*\).*/\1\2'$TLS_SERVER_CERT'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl_key_file[[:blank:]]*=[[:blank:]]*\).*/\1\2'$TLS_SERVER_KEY'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*ssl_ca_file[[:blank:]]*=[[:blank:]]*\).*/\1\2'$TLS_BUNDLE'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*log_destination[[:blank:]]*=[[:blank:]]*\).*/\1\2'syslog'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*logging_collector[[:blank:]]*=[[:blank:]]*\).*/\1\2on/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*log_directory[[:blank:]]*=[[:blank:]]*\).*/\1\2'pg_log'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*log_filename[[:blank:]]*=[[:blank:]]*\).*/\1\2'postgresql-%Y-%m-%d_%H%M%S.log'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*log_file_mode[[:blank:]]*=[[:blank:]]*\).*/\1\2'0644'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*log_truncate_on_rotation[[:blank:]]*=[[:blank:]]*\).*/\1\2on/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*log_rotation_size[[:blank:]]*=[[:blank:]]*\).*/\1\210MB/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*syslog_facility[[:blank:]]*=[[:blank:]]*\).*/\1\2'LOCAL0'/;\
s/\(^[[:blank:]]*\)#*\([[:blank:]]*syslog_ident[[:blank:]]*=[[:blank:]]*\).*/\1\2'$PGUSER'/" $PGDATA/postgresql.conf || let RC+=1

# Generate version-agnostic postgres command
ln -s /usr/lib/postgresql/$PGVER/bin/postgres /usr/local/bin/postgres && chmod 777 /usr/local/bin/postgres || let RC+=1

exit $RC
