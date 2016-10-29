# COP

COP is the name for Membership Services in v1.0 of Hyperledger Fabric.  COP is not an acronym.  The name "COP" was selected because of the following.

  * COP provides police-like security functionality for Hyperledger Fabric.  It is the "fabric COP"; 
  * COP is shorter and easier to say and write than “Membership Services v1.0” :-)

See the [COP design doc](https://docs.google.com/document/d/1TRYHcaT8yMn8MZlDtreqzkDcXx0WI50AV2JpAcvAM5w) for information on what COP will provide.

## Getting Started

COP is still being developed.
This section describes what you can currently do with COP.

### Prerequisites

* Go 1.6+ installation or later
* **GOPATH** environment variable is set correctly
* **COP** environment variable is set to **$GOPATH/src/github.com/hyperledger/fabric-cop**

### Download and build the cop executable

The following shows how to download and build the cop executable (i.e. the 'cop' binary).
Be sure to replace **YOUR-ID** appropriately.
   
```
# go get github.com/go-sql-driver/mysql
# go get github.com/lib/pq
# cd $GOPATH/src/github.com/hyperledger
# git clone ssh://YOUR-ID@gerrit.hyperledger.org:29418/fabric-cop
# cd fabric-cop
# make cop
```

The executable is at `$COP/bin/cop`.

### Explore the COP CLI

The following shows the cop usage message:


```
# cd $COP/bin
# ./cop
cop client       - client related commands
cop server       - server related commands
cop cfssl        - all cfssl commands

For help, type "cop client", "cop server", or "cop cfssl".
```

The COP client and server commands are what you will use.  However, since COP is built on top of [CFSSL](https://github.com/cloudflare/cfssl) and CFSSL has it's own CLI, you may issue any cfssl command with the `cop cfssl` command prefix.

### Initialize the COP server

For now, you must use CFSSL directly to initialize the key material for the COP server as follows.  This will be easier once the `cop server init` command is implemented.

```
# cd $COP/testdata
# go get -u github.com/cloudflare/cfssl/cmd/cfssl...
# $GOPATH/bin/cfssl gencert -initca config.json | $GOPATH/bin/cfssljson -bare cop
# mv cop.pem cop-cert.pem
```
For more information on CFSSL, click [here](https://github.com/cloudflare/cfssl).

### Start the COP server

Execute the following commands to start the COP server.  If you would like to specify debug-level logging,
set the `COP_DEBUG` environment variable to `true`.  And if you would like to run this in the background, append the "&" character to the command.

```
# cd $COP/bin
# ./cop server start -ca ../testdata/cop-cert.pem -ca-key ../testdata/cop-key.pem -config ../testdata/cop.json
```

It is now listening on localhost port 8888.

You can customize your COP config file at `../testdata/cop.json`.  For example,
if you want to disable authentication, you can do so by setting `authentication` to
`false`.  This prevents the COP server from looking at the authorization header.
Auhentication is added by COP since CFSSL does not perform authentication.  A standard HTTP
basic authentication header is required for the enroll request.  All other requests
to the COP server will require a JWT-like token, but this work is not yet complete.

### Enroll the admin client

See the `$COP/testdata/cop.json` file and note the "admin" user with a password of "adminpw".
The following command gets an ecert for the admin user.

```
# cd $COP/bin
# ./cop client enroll admin adminpw ../testdata/csr.json http://localhost:8888
```

### Run the cop tests

To run the cop test, do the following.

WARNING: You must first stop the cop server which you started above; otherwise, it will fail with a port binding error.

```
# cd $COP
# make tests
```
   
   
  
