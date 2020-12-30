## Fabric CA FVT tests for Continuous Integration

### Building the test image

The tests scripts that will run are in `scripts/fvt`.

From the repository root, issue `make docker-fvt` to generate the docker test
image.  To remove build artifacts of the docker fvt test image, run `make
docker-clean`.

### Running the fvt tests

Once the test image is successfully built, execute

```sh
docker run -v $PWD:/opt/gopath/src/github.com/hyperledger/fabric-ca hyperledger/fabric-ca-fvt
```

By default, the resulting container will run `scripts/run_fvt_tests` in the
environment provided by the `hyperledger/fabric-ca-fvt` docker image. Output
will go to the terminal.

### Interacting with the test container

To start a command-line instance of the test container without automatically
running the tests, issue

```sh
docker run -v $PWD:/opt/gopath/src/github.com/hyperledger/fabric-ca -ti hyperledger/fabric-ca-fvt bash
```

This mounts the source code from the host into the container. You can make any
changes you want, then manually issue `make fvt-tests` from inside the
container.

### Running All Tests

To execute all of the tests that will run in CI, issue

```sh
make all-tests fvt-tests
```

This will build a docker-fvt test image and run all of the unit tests,
integration tests, and fvt tests.

### Creating tests

You may add additional tests (essentially any scripts or executables, in any
language, that generates a return code and follows the naming convention
`*test.sh`) by placing them in the `scripts/fvt` directory. You may invoke
them directly within an interactive test container, or rely on the image's
default command run all of the fvt tests.  Note that each test in the fvt
directory will be run twice: once using TLS and once without using TLS.
Consequently, the tests should be written to run in either environment.

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
