#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
FROM _NS_/fabric-baseimage:_BASE_TAG_

ENV PATH="/usr/local/go/bin/:${PATH}" \
    DEBIAN_FRONTEND="noninteractive" \
    GOPATH="/opt/gopath" \
    PGDATA="/usr/local/pgsql/data/" \
    PGUSER="postgres" \
    PGPASSWORD="postgres" \
    PGSSLCERT="/etc/hyperledger/fabric-ca/FabricTlsClientEEcert.pem" \
    PGSSLKEY="/etc/hyperledger/fabric-ca/FabricTlsClientEEkey.pem" \
    PGVER=_PGVER_ \
    HOSTADDR="127.0.0.1" \
    LDAPPORT="389" \
    LDAPUSER="admin" \
    LDAPPASWD="adminpw" \
    FABRIC_CA_DATA=/etc/hyperledger/fabric-ca \
    TLS_BUNDLE=FabricTlsPkiBundle.pem \
    TLS_SERVER_CERT=FabricTlsServerEEcert.pem \
    TLS_SERVER_KEY=FabricTlsServerEEkey.pem \
    TLS_CLIENT_CERT=FabricTlsClientEEcert.pem \
    TLS_CLIENT_KEY=FabricTlsClientEEkey.pem \
    MYSQLDATA=/var/lib/mysql

# setup scripts for slapd, postgres, mysql, and openssl
ADD payload/fabric-ca-fvt.tar.bz2 $FABRIC_CA_DATA
RUN chmod +x $FABRIC_CA_DATA/*sh
RUN cd $FABRIC_CA_DATA
RUN $FABRIC_CA_DATA/tls_pki.sh
RUN chmod 600 $FABRIC_CA_DATA/$TLS_SERVER_KEY
RUN chmod 600 $FABRIC_CA_DATA/$TLS_CLIENT_KEY

# Avoid ERROR:
#   invoke-rc.d: policy-rc.d denied execution of start.
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

RUN $FABRIC_CA_DATA/system_update.sh
RUN $FABRIC_CA_DATA/postgres_setup.sh
RUN $FABRIC_CA_DATA/slapd_setup.sh
RUN $FABRIC_CA_DATA/mysql_setup.sh

# Install fabric-ca dependencies
RUN go get github.com/go-sql-driver/mysql
RUN go get github.com/lib/pq

# Add docker-built execs for (potentially) alternative architecture
COPY payload/fabric-ca-client payload/fabric-ca-server /usr/local/bin/
RUN chmod +x /usr/local/bin/fabric-ca-client /usr/local/bin/fabric-ca-server

WORKDIR ${GOPATH}/src/github.com/hyperledger/fabric-ca
RUN cp $FABRIC_CA_DATA/start.sh /
ENTRYPOINT [ "/start.sh" ]
CMD ["make", "fvt-tests"]
