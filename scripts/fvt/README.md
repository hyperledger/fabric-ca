# Fabric CA FVT tests for Continuous Integration

The tests that will run are in ``$GOPATH/src/github.com/hyperledger/fabric-ca/scripts/fvt``

Once the prerequites have been satisfied (see below), run

``make fvt-tests``

from the ``$GOPATH/src/github.com/hyperledger/fabric-ca/`` directory.
Depending on the security settings and options requested, root authority may be required. Precede the

``su -c 'make fvt-tests'``

This is also true of the ``fabric-ca_setup.sh`` documented below.

Tests have been verified to run on Ubuntu linux.

### Prerequisites
* Go 1.6+ installation or later
* GOPATH environment variable is set correctly
* ``fabric-ca`` executable is in ``$GOPATH/src/github.com/hyperledger/fabric-ca/bin/``
* haproxy for high availability testing
* python 2.7
* jq for JSON processing

Optionally, to run the tests using external database support (postgres, mysql), install the appropriate packages (mysql-server, mysql-server-core, mysql-common, postgresql)

All of the above prerequisites can met by running the setup script ``fabric-ca_setup.sh`` in ``$GOPATH/src/github.com/hyperledger/fabric-ca/scripts/``:
```
   fabric-ca_setup.sh -I   # install prerequsites
   fabric-ca_setup.sh -B   # build the CA executable
```

For example, to initialze the fabric-ca server, run haproxy, and four instances of the server using postgres:
```
   fabric-ca_setup.sh -X -S -I -d postgres -n4
```

To list all running instances of the server and the active database from the above command:
```
   fabric-ca_setup.sh -L -d postgress
```

To stop haproxy and all running instances of the server:
```
   fabric-ca_setup.sh -R
```