#!/bin/bash
numInstances=1
if test -n "$1" ; then
  numInstances=$1
fi
pushd scripts/fvt
./fabric-ca_setup.sh -D -X -I -S -n$numInstances -m10 -d postgres -T
popd
# Docker requires your command to keep running in the foreground. Otherwise, it thinks
# that command has stopped and shutsdown the container. Since fabric-ca_setup.sh starts
# fabric ca server in background and exits, we want this script to run in foreground and
# not return so the container in daemon mode continues to run for ever until it is stopped
tail -f /dev/null
