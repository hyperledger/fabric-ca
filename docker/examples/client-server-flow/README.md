# To build a docker image with fabric-ca
```sh
$ cd /path/to/fabric-ca; make docker
```

# Setup environment variables (optional)
If you want to use your own defined certificates, be sure to save these
certificates in the /var/hyperledger/fabric/.fabric-ca directory in your environment.
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
## Fabric CA configuration file
This file contains users, database setup, groups, and signing information)
sample values for server: server-config.json, server-psql.json
sample values for client: client-config.json
```sh
$ export FABRIC_CA_CONFIG=<Fabric CA configuration file>
```
## CSR (Certificate Signing Request) config file
default value: csr.json
```sh
$ export CSR_CONFIG=<CSR configuration file>
```

# Certificate private and public files
If you are using certificates or config files outside of the default values,
be sure to save the desired files to the developer's local directories. The
certificates should be saved to the `/var/hyperledger/fabric/.fabric-ca` directory
and the config files should be saved to the `/var/hyperledger/fabric_ca_config`
directory.

You can also generate the certificates by running the following script that
outputs server.pem and server-key.pem files and saves them to your $HOME/.fabric-ca
directory.
```sh
$ fabric-ca server init /path/to/fabric-ca/config/csr.json
```

# To execute the fabric-ca server and fabric-ca clients
```sh
$ docker-compose -f docker-compose-fabric-ca-cluster.yml up --force-recreate -d
```

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
s
