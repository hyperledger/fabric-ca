# Fabric CA FVT tests for Continuous Integration

The tests that will run are in

&nbsp;&nbsp;&nbsp;``$GOPATH/src/github.com/hyperledger/fabric-ca/scripts/fvt``

From ``${GOPATH}/src/github.com/hyperledger/fabric-ca``, issue

&nbsp;&nbsp;&nbsp;``make docker-fvt``

to generate the docker test image.

Then from ``${GOPATH}/src/github.com/hyperledger/fabric-ca``, issue

&nbsp;&nbsp;&nbsp;``docker run -v $PWD:/opt/gopath/src/github.com/hyperledger/fabric-ca hyperledger/fabric-ca-fvt``



To start an instance without automatically running the tests, issue

&nbsp;&nbsp;&nbsp;``docker run -v $PWD:/opt/gopath/src/github.com/hyperledger/fabric-ca -ti hyperledger/fabric-ca-fvt bash``

Snce the source code is mounted from your host, you can make any changes you want, then issue ``make docker-fvt``
