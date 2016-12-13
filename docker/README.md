# To build a docker image with cop
```sh
$ docker build fabric-cop -t fabric-cop:latest
```

# Setup environment variables (optional)
If you want to use your own defined certificates, be sure to save these
certificates in the /var/hyperledger/fabric/.cop directory in your environment.
Then set the following environment variables accordingly.

## Public key
default value: ec.pem
```sh
$ export CA_CERTIFICATE=<public key pem file>
```
## Private key
default value: ec-key.pem
```sh
$ export CA_KEY_CERTIFICATE=<private key pem file>
```
## COP configuration file
This file contains users, database setup, groups, and signing information)
default value: cop.json
```sh
$ export COP_CONFIG=<COP configuration file>
```
## CSR (Certificate Signing Request) config file
default value: csr.json
```sh
$ export CSR_CONFIG=<CSR configuration file>
```
```

# Certificate private and public files
If you are using certificates or config files outside of the default values,
be sure to save the desired files to the developer's local directories. The
certificates should be saved to the `/var/hyperledger/fabric/.cop` directory
and the config files should be saved to the `var/hyperledger/cop_config`
directory.

You can also generate the certificates by running the following script that
outputs server.pem and server-key.pem files and saves them to your $HOME/.cop
directory.
```sh
$ cop server init /path/to/cop/config/csr.json
```

# To execute the cop server and cop clients
```sh
$ docker-compose -f docker-compose-cop-cluster.yml up --force-recreate -d
```

