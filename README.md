# Fabric CA Developer's Guide

This is the Developer's Guide for Fabric CA, which is a Certificate Authority for Hyperledger Fabric.

See [User's Guide for Fabric CA](https://hyperledger-fabric-ca.readthedocs.io) for information on how to use Fabric CA.

## Prerequisites

* Go 1.11.5 installation or later
* **GOPATH** environment variable is set correctly
* docker version 17.06 or later
* docker-compose version 1.14 or later
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
4. **util/csp.go** contains the Crypto Service Provider implementation.
5. **lib/dbutil** contains database utility functions.
6. **lib/ldap** contains LDAP client code.
7. **lib/spi** contains Service Provider Interface code for the user registry.
8. **lib/tls** contains TLS related code for server and client.
9. **util** contains various utility functions.

## Additional info

## Profiling
Fabric CA server can be profiled two ways, namely, using benchmarks and by retrieving profiling data from the server (at /debug/pprof/ endpoint) while running load.

### Benchmarks
You can profile the benchmarks by running `make bench-cpu` or `make bench-mem` commands. You can profile benchmarks in one package or all the packages using these make targets. For example, to profile benchmarks in the *lib* package, run: `make bench-cpu pkg=github.com/hyperledger/fabric-ca/lib`. This will create **bench-cpu.prof**, **lib.test** and **bench** files in the *lib* folder. The **bench** file will contain benchmark stats: bytes/operation, allocations/operation and nanoseconds/operation. **lib.test** file is the executable and **bench-cpu.prof** contains cpu profile information. To analyze the profile, run: `go tool pprof lib.test bench-cpu.prof`. Similarly, you can run `make bench-mem pkg=github.com/hyperledger/fabric-ca/lib` to perform memory profiling of the benchmarks in the *lib* package. The **bench-mem.prof** file contains memory profile information.

If you run `make bench-cpu` or `make bench-mem` without *pkg* variable, benchmarks in each package are run with cpu or memory profiling. So, executable, benchmark output, and profile info files are created in each package folder. You need to analyze these profiles separately.

### Whole server
To enable profiling on the server, set the FABRIC_CA_SERVER_PROFILE_PORT environment
variable to a valid, available port number and start the server. The server will start listening for profile requests at the */debug/pprof/* HTTP endpoint and the specified port. Then run `go tool pprof` with server's profiling URL (http://<server host>:<profiling port>/debug/pprof/<profile|heap|block>) as an argument, it will download and examine a live profile.

You can start the server in the FVT image by running following docker command from the fabric-ca root directory:

`docker run -p 8888:8888 -p 8054:8054 -v $PWD:/opt/gopath/src/github.com/hyperledger/fabric-ca -e FABRIC_CA_SERVER_PROFILE_PORT=8054 --name loadTest -td hyperledger/fabric-ca-fvt test/fabric-ca-load-tester/launchServer.sh 1`

Then start the load by running `/test/fabric-ca-load-tester/runLoad.sh -B`

In other window, you can start profiling by running (assuming load test takes about a minute to complete):

`curl http://localhost:8054/debug/pprof/profile?seconds=60 > load-cpu.prof`

then analyze the profile:

`go tool pprof bin/fabric-ca-server load-cpu.prof`

OR simply run:

`go tool pprof -seconds=60 -output=load-cpu.prof http://localhost:8054/debug/pprof/profile`

You can use commands like *top*, *top -cum*, *list* and *web* to look at the top consumers, list the code to see the hotspots and to view the graph in a browser. You can run `go tool pprof -h` to view all the options supported by the pprof tool

You can also use [**go-torch**](https://github.com/uber/go-torch) tool to analyze the profile:

`go-torch bin/fabric-ca-server load-cpu.prof`

### Profiling Fabric CA client
To enable profiling on the client, set the FABRIC_CA_CLIENT_PROFILE_MODE environment variable to either "heap" or "cpu" to enable heap, cpu profiling respectively. A file containing profiling data is created in the present working directory of the client. Heap profiling data is written to **mem.pprof** and cpu profiling data is written to **cpu.pprof**. You can run `go tool pprof <client executable> <profiling file>` to analyze the profiling data.

### Profiling links
https://blog.golang.org/profiling-go-programs
https://medium.com/@hackintoshrao/daily-code-optimization-using-benchmarks-and-profiling-in-golang-gophercon-india-2016-talk-874c8b4dc3c5
https://www.youtube.com/watch?v=2h_NFBFrciI
https://software.intel.com/en-us/blogs/2014/05/10/debugging-performance-issues-in-go-programs
http://www.soroushjp.com/2015/01/27/beautifully-simple-benchmarking-with-go/
https://vinceyuan.github.io/profiling-memory-usage-of-a-go-app/
https://www.youtube.com/watch?v=N3PWzBeLX2M&feature=youtu.be
https://www.youtube.com/watch?v=oorX84tBMqo&feature=youtu.be

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


## Continuous Integration

Please have a look at [Continuous Integration Process](docs/source/ca-ci.md)

## License <a name="license"></a>

Hyperledger Project source code files are made available under the Apache License, Version 2.0 (Apache-2.0), located in the [LICENSE](LICENSE) file. Hyperledger Project documentation files are made available under the Creative Commons Attribution 4.0 International License (CC-BY-4.0), available at http://creativecommons.org/licenses/by/4.0/.
