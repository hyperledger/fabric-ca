FROM hyperledger/fabric-cop-runtime:_TAG_
ENV COP_HOME /etc/hyperledger/fabric-cop
RUN mkdir -p $COP_HOME /var/hyperledger/fabric-cop
COPY payload/cop /usr/local/bin

# Copy the configuration files
ADD payload/sampleconfig.tar.bz2 $COP_HOME
#COPY payload/cop.json /config/cop.json
#COPY payload/cop-psql.json /config/cop-psql.json
#COPY payload/csr.json /config/csr.json
#COPY payload/cop_client.json /etc/hyperledger/fabric-cop/cop_client.json

# Copy the same certificates that are currently hardcoded into the peers
COPY payload/root.pem /.cop/root.pem
COPY payload/tls_client-cert.pem /.cop/tls_client-cert.pem
COPY payload/tls_client-key.pem /.cop/tls_client-key.pem
COPY payload/ec-key.pem /.cop/ec-key.pem
COPY payload/ec.pem /.cop/ec.pem

EXPOSE 8888
CMD cop server start -address 0.0.0.0 -config $COP_HOME/cop.json
