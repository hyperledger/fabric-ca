##Fabric CA FVT tests for Continuous Integration<br>

###Building the test image
The tests that will run are in  
&nbsp;&nbsp;&nbsp;``$GOPATH/src/github.com/hyperledger/fabric-ca/scripts/fvt``  

From ``${GOPATH}/src/github.com/hyperledger/fabric-ca``, issue  
&nbsp;&nbsp;&nbsp;``make docker-fvt``  
to generate the docker test image.

You can verify the successful build of the test images by issuing  
&nbsp;&nbsp;&nbsp;``docker images``  
and look for the ``hyperledger/fabric-ca-fvt`` image in the output.  

To remove build artifacts of the docker fvt test image, issue  
&nbsp;&nbsp;&nbsp;``make docker-clean``<br>

###Running the fvt tests
Once the test image is successfully built, from ``${GOPATH}/src/github.com/hyperledger/fabric-ca``, issue  
&nbsp;&nbsp;&nbsp;``docker run -v $PWD:/opt/gopath/src/github.com/hyperledger/fabric-ca hyperledger/fabric-ca-fvt``  
By default, the resulting container will run ``make fvt-tests`` in the environment provided by the hyperledger/fabric-ca-fvt docker image. Output will go to the associated terminal.<br>

###Interactively interfacing with the test container
To start a command-line instance of the test container without automatically running the tests, issue  
&nbsp;&nbsp;&nbsp;``docker run -v $PWD:/opt/gopath/src/github.com/hyperledger/fabric-ca -ti hyperledger/fabric-ca-fvt bash``

Since the source code is mounted from your host, you can make any changes you want, then manually issue ``make fvt-tests`` from inside the container.<br>

###Running continuous integration tests
To simulate a continuous integration test run, issue:  
&nbsp;&nbsp;&nbsp;``make ci-tests``  
This will build a docker-fvt test image and run all of the currently defined unit tests, as well as all fvt tests.<br>

###Creating tests
You may add additional tests (essentially any scripts or executables, in any language, that generates a return code and follows the naming convention `*test.sh`) by placing them in the ``$GOPATH/src/github.com/hyperledger/fabric-ca/scripts/fvt`` directory. You may invoke them directly within an interactive test container, or rely on the image's default command to succesively run all of the tests in the `$GOPATH/src/github.com/hyperledger/fabric-ca/scripts/fvt`` directory. Note that each test in the fvt directory will be run twice: once using TLS and once without using TLS. Consequently, the tests should be written to run in either environment.

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
s
