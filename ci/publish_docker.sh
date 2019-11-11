#!/bin/bash
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
set -eu -o pipefail

make docker
docker login --username "${DOCKER_USERNAME}" --password "${DOCKER_PASSWORD}"
docker tag "hyperledger/fabric-ca" "hyperledger/fabric-ca:amd64-${RELEASE}"
docker push "hyperledger/fabric-ca:amd64-${RELEASE}"

wget -qO "$PWD/manifest-tool" https://github.com/estesp/manifest-tool/releases/download/v1.0.0/manifest-tool-linux-amd64
chmod +x ./manifest-tool
./manifest-tool push from-args --platforms linux/amd64 --template "hyperledger/fabric-ca:amd64-${RELEASE}" --target "hyperledger/fabric-ca:${RELEASE}"
./manifest-tool push from-args --platforms linux/amd64 --template "hyperledger/fabric-ca:amd64-${RELEASE}" --target "hyperledger/fabric-ca:$(sed 's/..$//' <<< ${RELEASE})"
./manifest-tool push from-args --platforms linux/amd64 --template "hyperledger/fabric-ca:amd64-${RELEASE}" --target "hyperledger/fabric-ca:latest"
