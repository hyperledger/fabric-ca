#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
FROM _BASE_NS_/fabric-baseos:_BASE_TAG_
ENV FABRIC_CA_HOME /etc/hyperledger/fabric-ca-server
ARG FABRIC_CA_DYNAMIC_LINK=false
RUN mkdir -p $FABRIC_CA_HOME /var/hyperledger/fabric-ca-server
COPY payload/fabric-ca-client /usr/local/bin
RUN chmod +x /usr/local/bin/fabric-ca-client
COPY payload/fabric-ca-server /usr/local/bin
RUN chmod +x /usr/local/bin/fabric-ca-server
RUN apt-get update && apt-get install -y netcat && rm -rf /var/cache/apt

# Copy the same certificates that are currently hardcoded into the peers
ADD payload/fabric-ca.tar.bz2 $FABRIC_CA_HOME

EXPOSE 7054
CMD fabric-ca-server start -b admin:adminpw
