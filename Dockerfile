#
# Copyright contributors to the Hyperledger Fabric CA project
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# 	  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER} as builder

ARG GO_TAGS
ARG GO_LDFLAGS

ADD . /build/fabric-ca
WORKDIR /build/fabric-ca

#
# Important!  When compiling the fabric-ca binaries, the external C
# dependency on golang-sqlite must be linked statically into the
# output binary.  If the binaries are dynamically linked, the routines
# will not be able to resolve the fcntl64 routine, which is not available
# in the alpine runtime (even with musl and gcompat.)
#
RUN go build \
    -o bin/fabric-ca-server \
    -tags "${GO_TAGS}" \
    -ldflags "${GO_LDFLAGS}" \
    github.com/hyperledger/fabric-ca/cmd/fabric-ca-server

RUN go build \
    -o bin/fabric-ca-client \
    -tags "${GO_TAGS}" \
    -ldflags "${GO_LDFLAGS}" \
    github.com/hyperledger/fabric-ca/cmd/fabric-ca-client


FROM alpine:${ALPINE_VER}
RUN apk add --no-cache \
    gcompat \
	tzdata;

COPY --from=builder /build/fabric-ca/bin /usr/local/bin

ENV FABRIC_CA_HOME /etc/hyperledger/fabric-ca-server
EXPOSE 7054

CMD fabric-ca-server start -b admin:adminpw
