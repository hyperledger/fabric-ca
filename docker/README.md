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
