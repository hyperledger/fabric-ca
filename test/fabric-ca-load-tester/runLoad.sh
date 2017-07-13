#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is used to run the load driver that drives load against a
# Fabric CA server or cluster of servers. The Fabric CA server URL and
# load characteristics can be defined in the testConfig.yml file, which
# must be located in the current working directory.
#
# When run with -B option, it will build the load driver and then runs it.

pushd $GOPATH/src/github.com/hyperledger/fabric-ca/test/fabric-ca-load-tester
if [ "$1" == "-B" ]; then
  echo "Building fabric-ca-load-tester..."
  if [ "$(uname)" == "Darwin" ]; then
    # On MacOS Sierra use -ldflags -s flags to work around "Killed: 9" error
    go build -o fabric-ca-load-tester -ldflags -s main.go testClient.go
  else
    go build -o fabric-ca-load-tester main.go testClient.go
  fi
fi
echo "Running load"
./fabric-ca-load-tester -config testConfig.yml
rm -rf msp
rm -rf fabric-ca-load-tester
popd
