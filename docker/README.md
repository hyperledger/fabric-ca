# To build a docker image with fabric-ca
```sh
$ cd /path/to/fabric-ca; make docker
```

# Docker compose files

## Server
The server directory contains a docker-compose file to run the fabric-ca-server.
To start the server:
```sh
$ cd path/to/fabric-ca/docker/server; docker-compose up
```

## Examples

### client-server-flow
This example generic client and server flows.
To run the example:
```sh
$ cd path/to/fabric-ca/docker/examples/client-server-flow; docker-compose up
```

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
s
