# Fabric CA

The fabric-ca is a Certificate Authority for Hyperledger Fabric v1.0 and later.

It consists of both a serve and a client component.

It provides features including:  
* registration of identities;
* enrollment of identities and issuance of enrollment certificates (ECerts);
* issuance of transaction certificates (TCerts) given proof of ownership
  of an ECert;
* certificate renewal and revocation.

See the [Fabric-CA design doc](https://docs.google.com/document/d/1TRYHcaT8yMn8MZlDtreqzkDcXx0WI50AV2JpAcvAM5w) for design documentation.

## Getting Started

### Prerequisites

* Go 1.7+ installation or later
* **GOPATH** environment variable is set correctly
* In this document, **FABRIC_CA** refers to the **$GOPATH/src/github.com/hyperledger/fabric-ca** directory

### Install fabric-ca

To install fabric-ca, simply type:
```
# go get github.com/hyperledger/fabric-ca
```

For fabric-ca developers, you may do as follows to clone and build:

```
# mkdir -p $GOPATH/src/github.com/hyperledger
# cd $GOPATH/src/github.com/hyperledger
# git clone ssh://YOUR-ID@gerrit.hyperledger.org:29418/fabric-ca
# cd fabric-ca
# make
```
It will generate fabric-ca-server and fabric-ca-client in the directory named bin.

See the Makefile for various build targets and their descriptions.

### Explore the fabric-ca CLI

The following shows the fabric-ca-server usage message:


```
# cd bin
# ./fabric-ca-server
Usage:
  fabric-ca-server [command]

Available Commands:
  init        Initialize the fabric-ca server
  start       Start the fabric-ca server

Flags:
  -c, --config string   Configuration file (default "fabric-ca-server-config.yaml")
  -d, --debug           Enable debug logging
  -u, --user string     user:pass for bootstrap user is required to build default config if config file does not exist

Use "fabric-ca-server [command] --help" for more information about a command.



```

The following shows the fabric-ca-server usage message:
# ./fabric-ca-client

Usage:
  fabric-ca-client [command]

Available Commands:
  enroll      Enroll user
  reenroll    Reenroll user
  register    Register user
  revoke      Revoke user

Flags:
  -c, --config string     Configuration file (default "/root/.fabric-ca-client/fabric-ca-client-config.yaml")
  -d, --debug             Enable debug logging
  -e, --enrollid string   Enrollment ID
      --host string       Hostname (default "fabric-cop")
      --url string        URL of the Fabric-ca server (default "http://localhost:7054")

Use "fabric-ca-client [command] --help" for more information about a command.


### fabric-ca server configuration options

**tls_disable (Default: false)** - Setting to true will disable TLS

**max_enrollments (Default: 0)** - Allows you to specify how many times a user
can use its one time password to enroll itself. Default is 0, allows for
unlimited enrollments.

### Initialize the fabric-ca server  

Executing the following fabric-ca command will generate a private key and self-signed
x509 certificate to start the fabric-ca server in the `Start the fabric-ca server` section.
These two PEM files will be generated and stored in the directory
`$CA_CFG_PATH`: server-cert.pem and server-key.pem.
They can be used as input parameters to `-ca` and `-ca-key` in the command to
start the fabric-ca server.

```
# fabric-ca server init ../testdata/csr_dsa.json
```
The `../testdata/csr_dsa.json` file can be customized to generate x509
certificates and keys that support both RSA and Elliptic Curve (ECDSA).

The following setting is an example of the implementation of Elliptic Curve
Digital Signature Algorithm (ECDSA) with curve:
secp384r1 and Signature Algorithm: ecdsa-with-SHA384:

"algo": "ecdsa"  
"size": 384

The choice of algorithm and key size are based on security needs.

Elliptic Curve (ECDSA) offers the following curves and security levels:

| size        | ASN1 OID           | Signature Algorithm  |
|-------------|:-------------:|:-----:|
| 256      | prime256v1 | ecdsa-with-SHA256 |
| 384      | secp384r1      |   ecdsa-with-SHA384 |
| 521 | secp521r1     | ecdsa-with-SHA512 |

Likewise, these are the secure choices for RSA modulus:

| size        | Modulus (bits)| Signature Algorithm  |
|-------------|:-------------:|:-----:|
| 2048      | 2048 | sha256WithRSAEncryption |
| 4096      | 4096 | sha512WithRSAEncryption |

### TLS/SSL configuration - Client & fabric-ca Server

The steps below should be followed to set up a secure connection between client
and server.

1. The fabric-ca server should be started with the following options set in the fabric-ca
configuration file. The **tls_cert** and **tls_key** are used to set up the TLS
protocol. The **mutual_tls_ca** requires that client certificates be signed by
the specified CA and client is required to send its certificate. The configuration
file for the server should contain the following:
```
...
"tls_cert":"tls_certificate.pem",
"tls_key":"tls_key.pem",
"mutual_tls_ca":"CA_root_cert.pem",
...
```

2. On client side, a configuration file (client-config.json) should be created as
een below and placed in the client home directory. The **ca_certfiles** option is
the set of root certificate authorities that clients uses when verifying server
certificates. The **client** option contains one or more certificate chains to
present to the other side of the connection.
```
{
"ca_certfiles":["CA_root_cert.pem"],
"client":[{"keyfile":"client-key.pem","certfile":"client.pem"}]
}
```

Once all the certificates and key have been properly configured on both client
and server a secure connection should be established.

### TLS configuration - Database & Server

#### Postgres

When specifying the connection string for the Postgres database in the server
configuration file, we must indicate that we wish to use a secure connection.
The connection string should be set as indicated below.

```
"driver":"postgres",
"data_source":"host=localhost port=5432 user=Username password=Password dbname=fabric-ca sslmode=verify-full",
```
**sslmode** - Enable SSL.
  - **verify-full** - Always SSL (verify that the certification presented by the
    Postgres server was signed by a trusted CA and the Postgres server host name
     matches the one in the certificate).

We also need to set the TLS configuration in the fabric-ca server config file. If the
database server requires client authentication that a client cert and key file
needs to be provided. The following should be present in the fabric-ca server config:

```
"tls":{
  ...
  "db_client":{
    "ca_certfiles":["CA.pem"],
    "client":[{"keyfile":"client-key.pem","certfile":"client-cert.pem"}]
  }
},
```

**ca_certfiles** - The location of the root certificate file.

**certfile** - Client certificate file.

**keyfile** - Client key file.

#### MySQL

When specifying the connection string for the MySQL database in the server
configuration file, we must indicate that we wish to use a secure connection.
The connection string should be set with the **tls=custom** parameter as
indicated below.

```
...
"driver":"mysql",
"data_source":"root:rootpw@tcp(localhost:3306)/fabric-ca?parseTime=true&tls=custom",
...
```

In the configuration file for the fabric-ca server, we need to define the elements
below to establish a secure connection between fabric-ca server and MySQL server. If
the database server requires client authentication that a client cert and key
file needs to be provided.

```
"tls":{
  ...
  "db_client":{
    "ca_certfiles":["CA.pem"],
    "client":[{"keyfile":"client-key.pem","certfile":"client-cert.pem"}]
  }
},
```

**ca_certfiles** - The location of the root certificate file.

**certfile** - Client certificate file.

**keyfile** - Client key file.


### Start the fabric-ca server

Execute the following commands to start the fabric-ca server.  If you would like to
specify debug-level logging, set the `FABRIC_CA_DEBUG` environment variable to `true`.
And if you would like to run this in the background, append the "&" character to
the command.

In server-config.json, specify the following properties. They specify the file to where
the CA certificate and CA key are stored.

```
"ca_cert":"server-cert.pem",
"ca_key":"server-key.pem",
```

Run the following command to start fabric-ca server:

```
# fabric-ca server start -config ../testdata/server-config.json
```

It is now listening on localhost port 7054.

You can customize your fabric-ca config file at `../testdata/server-config.json`.  For example,
if you want to disable authentication, you can do so by setting `authentication` to
`false`.  This prevents the fabric-ca server from looking at the authorization header.
Auhentication is added by fabric-ca since CFSSL does not perform authentication.  A standard HTTP
basic authentication header is required for the enroll request.  All other requests
to the fabric-ca server will require a JWT-like token, but this work is not yet complete.

### Create Client Configuration File

The client requires a configuration file to enable TLS and successfully connect
to server. A sample client configuration file can be found at
`../testdata/client-config.json`. The configuration file is passed in using
a config flag.


The table below defines all the properties that can be set in the config file.

| Property    |                     Description                              |
|-------------|--------------------------------------------------------------|
|serverURL    | URL of the server                                            |
|ca_certfiles | File path to root certificate of which server certificate is signed by    |
|keyfile      | File path to client TLS key on file system                   |
|certfile     | File path to client TLS certificate on file system           |

### Enroll the admin client

See the `FABRIC_CA/testdata/server-config.json` file and note the "admin" user with a password of "adminpw".
The following command gets an ecert for the admin user.

```
# fabric-ca client enroll -config ../testdata/client-config.json admin adminpw http://localhost:7054
```

The enrollment certificate is stored at `$FABRIC_CA_ENROLLMENT_DIR/cert.pem` by default, but a different
path can be specified by setting the `FABRIC_CA_CERT_FILE` environment variable to an absolute path name or a path relative to the current working directory.

The enrollment key is stored at `$FABRIC_CA_ENROLLMENT_DIR/key.pem` by default, but a different
path can be specified by setting the `FABRIC_CA_KEY_FILE` environment variable to an absolute path name or a path relative to the current working directory.

The default value of the `FABRIC_CA_ENROLLMENT_DIR` environment variable is `$CA_CFG_PATH`.

The default value of the `CA_CFG_PATH` environment variable is `$HOME/fabric-ca`.

### Reenroll

Suppose your enrollment certificate is about to expire.  You can issue the reenroll command
to renew your enrollment certificate as follows.  Note that this is identical to the enroll
command except no username or password is required.  Instead, your previously stored private
key is used to authenticate to the fabric-ca server.

```
# fabric-ca client reenroll -config ../testdata/client-config.json http://localhost:7054
```

The enrollment certificate and enrollment key are stored in the same location as described in the previous section for the `enroll` command.

You can specify a new Certificate Signing Request JSON information when issue the reenroll command

```
# fabric-ca client reenroll -config ../testdata/client-config.json http://localhost:7054 ../testdata/csr.json
```

### Register a new user

The user performing the register request must be currently enrolled, and also
this registrar must have the proper authority to register the type of user being
registered. The registrar must have been enrolled with attribute
"hf.Registrar.DelegateRoles". The DelegateRoles attribute specifies the types
this registrar is allowed to register.

For example, the attributes for a registrar might look like this:

```
"attrs": [{"name":"hf.Registrar.DelegateRoles", "value":"client,user"}]

```

The registrar should then create a JSON file as defined below for the user being
registered.

registerrequest.json:

```
{
  "id": "User1",
  "type": "client",
  "group": "bank_a",
  "attrs": [{"name":"AttributeName","value":"AttributeValue"}]
}
```

The following command will register the user.

```
# fabric-ca client register -config ../testdata/client-config.json ../testdata/registerrequest.json http://localhost:7054
```

### LDAP

The fabric-ca server can be configured to read from an LDAP server.

In particular, the fabric-ca server may connect to an LDAP server to do the following:

   * authenticate a user prior to enrollment, and   
   * retrieve a user's attribute values which is used for authorization.

In order to configure the fabric-ca server to connect to an LDAP server, add a section
of the following form to your fabric-ca server's configuration file:

```
{
   "ldap": {
       "url": "scheme://adminDN:pass@host[:port][/base]"
       "userfilter": "filter"
   }
```

where:  
   * `scheme` is one of *ldap* or *ldaps*;  
   * `adminDN` is the distinquished name of the admin user;  
   * `pass` is the password of the admin user;   
   * `host` is the hostname or IP address of the LDAP server;  
   * `port` is the optional port number, where default 389 for *ldap* and 636 for *ldaps*;  
   * `base` is the optional root of the LDAP tree to use for searches;  
   * `filter` is a filter to use when searching to convert a login user name to
   a distinquished name.  For example, a value of `(uid=%s)` searches for LDAP
   entries with the value of a `uid` attribute whose value is the login user name.
   Similarly, `(email=%s)` may be used to login with an email address.

The following is a sample configuration section for the default settings for the
 OpenLDAP server whose docker image is at `https://github.com/osixia/docker-openldap`.

```
 "ldap": {
    "url": "ldap://cn=admin,dc=example,dc=org:admin@localhost:10389/dc=example,dc=org",
    "userfilter": "(uid=%s)"
 },
```

See `FABRIC_CA/testdata/testconfig-ldap.json` for the complete configuration file with this section.
Also see `FABRIC_CA/scripts/run-ldap-tests` for a script which starts an OpenLDAP docker image, configures it,
runs the LDAP tests in FABRIC_CA/cli/server/ldap/ldap_test.go, and stops the OpenLDAP server.

##### When LDAP is configured, enrollment works as follows:

  * A fabric-ca client or client SDK sends an enrollment request with a basic authorization header.
  * The fabric-ca server receives the enrollment request, decodes the user/pass in the authorization header, looks up the DN (Distinquished Name) associated with the user using the "userfilter" from the configuration file, and then attempts an LDAP bind with the user's password. If successful, the enrollment processing is authorized and can proceed.

##### When LDAP is configured, attribute retrieval works as follows:

   * A client SDK sends a request for a batch of tcerts **with one or more attributes** to the fabric-ca server.  
   * The fabric-ca server receives the tcert request and does as follows:
       * extracts the enrollment ID from the token in the authorization header
       (after validating the token);
       * does an LDAP search/query to the LDAP server, requesting all of the
       attribute names received in the tcert request;
       * the attribute values are placed in the tcert as normal


### Setting up a cluster

Set up a proxy server. Haproxy is used in this example. Below is a basic
configuration file that can be used to get haproxy up and running. Change
hostname and port to reflect the settings of your fabric-ca servers.

haproxy.conf

```
global
      maxconn 4096
      daemon

defaults
      mode http
      maxconn 2000
      timeout connect 5000
      timeout client 50000
      timeout server 50000

listen http-in
      bind *:7054
      balance roundrobin
      server server1 <hostname:port>
      server server2 <hostname:port>
      server server3 <hostname:port>
```

#### Postgres

When starting the fabric-ca server, specify the database that you would like to
connect to.  In your fabric-ca configuration file, the following should be present for
a Postgres database:

server-config.json
```
...
"driver":"postgres",
"data_source":"host=localhost port=5432 user=Username password=Password dbname=fabric-ca",
...
```

Change "host" and "dbname" to reflect where your database is located and the
database you would like to connect to. Default port is used if none is specified.
Enter username and password for a user that has permission to connect to the
database.

Once your proxy, fabric-ca servers, and Postgres server are all running you can have
your client direct traffic to the proxy server which will load balance and direct
traffic to the appropriate fabric-ca server which will read/write from the Postgres
database.  

#### MySQL

When starting up the fabric-ca servers specify the database that you would like to
connect to. In your fabric-ca configuration file, the following should be present for
a Postgres database:

server-config.json
```
...
"driver":"mysql",
"data_source":"root:rootpw@tcp(localhost:3306)/fabric-ca?parseTime=true&tls=custom",
...
```

Change the host to reflect where your database is located. Change "root" and
"rootpw" to the username and password you would like to use to connec to the
database. The database is specified after the '/', specify the database you
would like to connect to. Default port is used if none is specified.

Once your proxy, fabric-ca servers, and database servers are all running you can have
your clients direct traffic to the proxy server which will load balance and
direct traffic to the appropriate fabric-ca server which will read/write from the
database.  

### Run the fabric-ca tests

To run the fabric-ca test, do the following.

WARNING: You must first stop the fabric-ca server which you started above; otherwise,
it will fail with a port binding error.

```
# cd FABRIC_CA
# make unit-tests
```

## Appendix

### Postgres SSL Configuration

**Basic instructions for configuring SSL on Postgres server:**
1. In postgresql.conf, uncomment SSL and set to "on" (SSL=on)
2. Place Certificate and Key files Postgress data directory.

Instructions for generating self-signed certificates for:
https://www.postgresql.org/docs/9.1/static/ssl-tcp.html

Note: Self-signed certificates are for testing purposes and should not be used
in a production environment

**Postgres Server - Require Client Certificates**
1. Place certificates of the certificate authorities (CAs) you trust in the file
 root.crt in the Postgres data directory
2. In postgresql.conf, set "ssl_ca_file" to point to the root cert of client (CA cert)
3. Set the clientcert parameter to 1 on the appropriate hostssl line(s) in pg_hba.conf.

For more details on configuring SSL on the Postgres server, please refer to the
following Postgres documentation: https://www.postgresql.org/docs/9.4/static/libpq-ssl.html


### MySQL SSL Configuration
**Basic instructions for configuring SSL on MySQL server:**
1. Open or create my.cnf file for the server. Add or un-comment the lines below
in [mysqld] section. These should point to the key and certificates for the
server, and the root CA cert.

Instruction on creating server and client side certs:
http://dev.mysql.com/doc/refman/5.7/en/creating-ssl-files-using-openssl.html

[mysqld]
ssl-ca=ca-cert.pem
ssl-cert=server-cert.pem
ssl-key=server-key.pem

Can run the following query to confirm SSL has been enabled.

mysql> SHOW GLOBAL VARIABLES LIKE 'have_%ssl';

Should see:
```
+---------------+-------+
| Variable_name | Value |
+---------------+-------+
| have_openssl  | YES   |
| have_ssl      | YES   |
+---------------+-------+
```

2. After the server-side SSL configuration is finished, the next step is to
create a user who has a privilege to access the MySQL server over SSL. For that,
log in to the MySQL server, and type:

mysql> GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%' IDENTIFIED BY 'password' REQUIRE SSL;
mysql> FLUSH PRIVILEGES;

If you want to give a specific ip address from which the user will access the
server change the '%' to the specific ip address.

**MySQL Server - Require Client Certificates**
Options for secure connections are similar to those used on the server side.

- ssl-ca identifies the Certificate Authority (CA) certificate. This option,
if used, must specify the same certificate used by the server.
- ssl-cert identifies the client public key certificate.
- ssl-key identifies the client private key.

Suppose that you want to connect using an account that has no special encryption
requirements or was created using a GRANT statement that includes the REQUIRE SSL
option. As a recommended set of secure-connection options, start the MySQL
server with at least --ssl-cert and --ssl-key, and invoke the fabric-ca server with
**ca_certfiles** option set in the fabric-ca server file.

To require that a client certificate also be specified, create the account using
the REQUIRE X509 option. Then the client must also specify the proper client key
and certificate files or the MySQL server will reject the connection. CA cert,
client cert, and client key are all required for the fabric-ca server.
