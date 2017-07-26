# Fabric CA Developer's Guide

This is the Developer's Guide for Fabric CA, which is a Certificate Authority for Hyperledger Fabric.

See [User's Guide for Fabric CA](https://hyperledger-fabric-ca.readthedocs.io) for information on how to use Fabric CA.

## Prerequisites

* Go 1.7+ installation or later
* **GOPATH** environment variable is set correctly
* docker version 17.03 or later
* docker-compose version 1.11 or later
* A Linux Foundation ID  (see [create a Linux Foundation ID](https://identity.linuxfoundation.org/))


## Contribution guidelines

You are welcome to contribute to Fabric CA!

The following are guidelines to follow when contributing:

1. See the general information about [contributing to fabric](http://hyperledger-fabric.readthedocs.io/en/latest/CONTRIBUTING.html).

2. To set up your development environment for doing common development tasks, see [bash_profile](https://github.com/hyperledger/fabric-ca/blob/master/scripts/bash_profile).  This contains variables and functions which can be copied directly into your `.bash_profile` file.  Even if you do not use bash, you should still find the functions instructive.  For example:  
   a. **clone** - pulls the latest fabric-ca code from gerrit and places it based on your GOPATH setting  
   b. **cdr** - cd to the fabric-ca repository root, which is equivalent to "cd $GOPATH/src/github.com/hyperledger/fabric-ca"  
   c. **gencov** - generates a test coverage report  

3. To run the unit tests manually:

   ```
   # cdr
   # make unit-tests
   ```

   The test coverage for each package must be 75% or greater.  If this fails due to insufficient test coverage, then you can run `gencov` to get a coverage report to see what code is not being tested.   Once you have added additional test cases, you can run `go test -cover` in the appropriate package to see the current coverage level.

   WARNING: Running the unit-tests may fail due to too many open file descriptors.
   Depending on where the failure occurs, the error message may not be obvious and may only say something similar to "unable to open database file".
   Depending on the settings on your host, you may need to increase the maximum number of open file descriptors.
   For example, the OSX default per-process maximum number of open file descriptors is 256.
   You may issue the following command to display your current setting:

   ```
   # ulimit -n
   256
   ```

   And the following command will increase this setting to 65536:

   ```
   # ulimit -n 65536
   ```

   Please note that this change is only temporary. To make it permanent, you will need to consult the documentation for your host operating system.

## Package overview

1. **cmd/fabric-ca-server** contains the main for the fabric-ca-server command.
2. **cmd/fabric-ca-client** contains the main for the fabric-ca-client command.
3. **lib** contains most of the code.  
   a) **server.go** contains the main Server object, which is configured by **serverconfig.go**.  
   b) **client.go** contains the main Client object, which is configured by **clientconfig.go**.  
4. **lib/csp** contains some functions related to the Crypto Service Provider.
5. **lib/dbutil** contains database utility functions.
6. **lib/ldap** contains LDAP client code.
7. **lib/spi** contains Service Provider Interface code for the user registry.
8. **lib/tls** contains TLS related code for server and client.
9. **util** contains various utility functions.

## Additional info

### Profiling Fabric CA server
To enable profiling on the server, set the FABRIC_CA_SERVER_PROFILE_PORT environment
variable to a valid, available port number and start the server. The server will start listening for profile requests at the specified port. Then run `go tool pprof` with server's profiling URL (http://<server host>:<profiling port>/debug/pprof/<profile|heap|block>) as an argument, it will download and examine a live profile.

### Profiling Fabric CA client
To enable profiling on the client, set the FABRIC_CA_CLIENT_PROFILE_MODE environment variable to either "heap" or "cpu" to enable heap, cpu profiling respectively. A file containing profiling data is created in the present working directory of the client. Heap profiling data is written to **mem.pprof** and cpu profiling data is written to **cpu.pprof**. You can run `go tool pprof <client executable> <profiling file>` to analyze the profiling data.

Run `go tool pprof -h` to view the options supported by the pprof tool. For more information on profiling, see https://blog.golang.org/profiling-go-programs

### FVT

See [FVT tests](scripts/fvt/README.md) for information on functional verification test cases.


### Updating the cfssl vendored package
Following are the steps to update cfssl package using version 1.0.8 of govendor tool. 

* Remove cfssl from vendor folder
   * cd $GOPATH/src/github.com/hyperledger/fabric-ca/vendor
   * govendor remove github.com/cloudflare/cfssl/...
   * rm -rf github.com/cloudflare/cfssl/

* Clone cfssl repo
   * cd $GOPATH/src/github.com/
   * mkdir cloudflare
   * cd cloudflare
   * git clone https://github.com/cloudflare/cfssl.git

* Add cfssl from $GOPATH to the vendor folder
   * cd $GOPATH/src/github.com/hyperledger/fabric-ca/vendor
   * govendor add github.com/cloudflare/cfssl/^
   * You can optionally specify revision or tag to add a particular revision of code to the vendor folder
      * govendor add github.com/cloudflare/cfssl/^@abc12032

* Remove sqlx package from cfssl vendor folder. This is because certsql.NewAccessor (called by fabric-ca) requires sqlx.db object to be passed from the same package. If we were to have sqlx package both in fabric-ca and cfssl vendor folder, go compiler will throw an error
   * rm -rf github.com/cloudflare/cfssl/vendor/github.com/jmoiron/sqlx

* Remove the packages that are added to the fabric-ca vendor folder that are not needed by fabric-ca


<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>
