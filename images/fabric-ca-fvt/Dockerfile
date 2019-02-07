#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
ARG BASEIMAGE_RELEASE
FROM hyperledger/fabric-baseimage:${BASEIMAGE_RELEASE} as fabric-ca-builder
ARG GO_LDFLAGS
ARG GO_TAGS

ADD . ${GOPATH}/src/github.com/hyperledger/fabric-ca
RUN go build -tags "${GO_TAGS}" -ldflags "${GO_LDFLAGS}" \
	-o /usr/local/bin/fabric-ca-server \
	github.com/hyperledger/fabric-ca/cmd/fabric-ca-server \
	&& go build -tags "${GO_TAGS}" -ldflags "${GO_LDFLAGS}" \
	-o /usr/local/bin/fabric-ca-client \
	github.com/hyperledger/fabric-ca/cmd/fabric-ca-client;


FROM hyperledger/fabric-baseimage:${BASEIMAGE_RELEASE}
ARG PG_VER

ENV PATH="/usr/local/go/bin/:${PATH}" \
    DEBIAN_FRONTEND="noninteractive" \
    GOPATH="/opt/gopath" \
    PGDATA="/usr/local/pgsql/data/" \
    PGUSER="postgres" \
    PGPASSWORD="postgres" \
    PGSSLCERT="/etc/hyperledger/fabric-ca/FabricTlsClientEEcert.pem" \
    PGSSLKEY="/etc/hyperledger/fabric-ca/FabricTlsClientEEkey.pem" \
    PGVER=${PG_VER} \
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
COPY --from=fabric-ca-builder \
	${GOPATH}/src/github.com/hyperledger/fabric-ca/images/fabric-ca-fvt/payload \
	${FABRIC_CA_DATA}
RUN chmod +x ${FABRIC_CA_DATA}/*sh
RUN cd ${FABRIC_CA_DATA}
RUN $FABRIC_CA_DATA/tls_pki.sh
RUN chmod 600 ${FABRIC_CA_DATA}/${TLS_SERVER_KEY}
RUN chmod 600 ${FABRIC_CA_DATA}/${TLS_CLIENT_KEY}

# Avoid ERROR:
#   invoke-rc.d: policy-rc.d denied execution of start.
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

RUN ${FABRIC_CA_DATA}/system_update.sh
RUN ${FABRIC_CA_DATA}/postgres_setup.sh
RUN ${FABRIC_CA_DATA}/slapd_setup.sh
RUN ${FABRIC_CA_DATA}/mysql_setup.sh

# Install fabric-ca dependencies
RUN go get github.com/go-sql-driver/mysql
RUN go get github.com/lib/pq

# Add docker-built execs for (potentially) alternative architecture
COPY --from=fabric-ca-builder /usr/local/bin /usr/local/bin

WORKDIR ${GOPATH}/src/github.com/hyperledger/fabric-ca
RUN cp ${FABRIC_CA_DATA}/start.sh /
ENTRYPOINT [ "/start.sh" ]
CMD ["scripts/run_fvt_tests"]
