#!/bin/bash -e

# Copyright IBM Corp All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

echo "metrics doc generation script starting..."

fabric_ca_dir="$(cd "$(dirname "$0")/.." && pwd)"
metrics_template="${fabric_ca_dir}/docs/source/metrics_reference.rst.tmpl"
metrics_doc="${fabric_ca_dir}/docs/source/metrics_reference.rst"

# install vendored gendoc
mkdir -p "${fabric_ca_dir}/build/tools"
GOBIN="${fabric_ca_dir}/build/tools" go install "${fabric_ca_dir}/vendor/github.com/hyperledger/fabric/common/metrics/cmd/gendoc"

# vendor gendoc package from hyperledger/fabric
gendoc_command=""${fabric_ca_dir}/build/tools/gendoc" github.com/hyperledger/fabric-ca/... -template ${metrics_template}"

cd "${fabric_ca_dir}" && ${gendoc_command} > "${metrics_doc}"
