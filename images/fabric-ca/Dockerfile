#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

###############################################################################
# Build image
###############################################################################

ARG UBUNTU_VER
FROM ubuntu:${UBUNTU_VER} AS builder

ARG TARGETARCH
ARG TARGETOS
ARG GO_VER
ARG GO_LDFLAGS
ARG GO_TAGS

RUN apt update && apt install -y \
    gcc \
    binutils-gold \
    git \
    curl \
    make

RUN curl -sL https://go.dev/dl/go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz | tar zxf - -C /usr/local
ENV GOBIN="/usr/local/go/bin"
ENV PATH="$GOBIN:$PATH"

ADD . /build/fabric-ca
WORKDIR /build/fabric-ca

RUN go install \
    -tags "${GO_TAGS}" \
    -ldflags "${GO_LDFLAGS}" \
    github.com/hyperledger/fabric-ca/cmd/fabric-ca-server

RUN go install \
    -tags "${GO_TAGS}" \
    -ldflags "${GO_LDFLAGS}" \
    github.com/hyperledger/fabric-ca/cmd/fabric-ca-client


###############################################################################
# Runtime image
###############################################################################

ARG UBUNTU_VER
FROM ubuntu:${UBUNTU_VER}

RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt install -y tzdata

ENV FABRIC_CA_HOME /etc/hyperledger/fabric-ca-server
COPY --from=builder /usr/local/go/bin /usr/local/bin

EXPOSE 7054

CMD [ "fabric-ca-server", "start", "-b", "admin:adminpw" ]
