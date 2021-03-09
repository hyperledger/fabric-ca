#!/bin/bash
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

make docker

docker login --username "${DOCKER_USERNAME}" --password "${DOCKER_PASSWORD}"

docker tag "hyperledger/fabric-ca" "hyperledger/fabric-ca:amd64-${RELEASE}"
docker push "hyperledger/fabric-ca:amd64-${RELEASE}"

docker tag "hyperledger/fabric-ca" "hyperledger/fabric-ca:${RELEASE}"
docker push "hyperledger/fabric-ca:${RELEASE}"

docker tag "hyperledger/fabric-ca" "hyperledger/fabric-ca:amd64-${TWO_DIGIT_RELEASE}"
docker push "hyperledger/fabric-ca:amd64-${TWO_DIGIT_RELEASE}"

docker tag "hyperledger/fabric-ca" "hyperledger/fabric-ca:${TWO_DIGIT_RELEASE}"
docker push "hyperledger/fabric-ca:${TWO_DIGIT_RELEASE}"
