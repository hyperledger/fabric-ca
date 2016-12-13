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

### Download and build the COP executable

The following shows how to download and build the COP executable (i.e. the 'COP' binary).
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

The following shows the COP usage message:


```
# cd $COP/bin
# ./cop
cop client       - client related commands
cop server       - server related commands
cop cfssl        - all cfssl commands

For help, type "cop client", "cop server", or "cop cfssl".
```

The COP client and server commands are what you will use.
However, since COP is built on top of [CFSSL](https://github.com/cloudflare/cfssl) and CFSSL has its own CLI,
you may issue any cfssl command with the `cop cfssl` command prefix.

### Initialize the COP server  

Executing the following "COP" command will generate a private key and self-signed x509 certificate to start the
COP server in the `Start the COP server` section. These two PEM files will be generated and stored in the directory
`$COP_HOME/.cop/`:  
server-cert.pem and server-key.pem.
They can be used as input parameters to `-ca` and `-ca-key` in the command to start the COP server.

```
# cd $COP/bin
# ./cop server init ../testdata/csr_dsa.json
```
The `../testdata/csr_dsa.json` file can be customized to generate x509 certificates and keys that support both
RSA and Elliptic Curve (ECDSA).

The following setting is an example of the implementation of Elliptic Curve Digital Signature Algorithm (ECDSA) with curve:
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
# ./cop client enroll admin adminpw http://localhost:8888
```

Note that this stores the enrollment material in the `$COP_HOME/client.json` file.

### Reenroll

Suppose your enrollment certificate is about to expire.  You can issue the reenroll command
to renew your enrollment certificate as follows.  Note that this is identical to the enroll
command except no username or password is required.  Instead, your previously stored private
key is used to authenticate to the COP server.

```
# cd $COP/bin
# ./cop client reenroll ../testdata/csr.json http://localhost:8888
```

Note that this updates the enrollment material in the `$COP_HOME/client.json` file.


### Register a new user

The user performing the register request must be currently enrolled, and also this registrar must have the proper authority to register the type of user being registered. The registrar must have been enrolled with attribute "hf.Registrar.DelegateRoles". The DelegateRoles attribute specifies the types this registrar is allowed to register.

For example, the attributes for a registrar might look like this:

```
"attrs": [{"name":"hf.Registrar.DelegateRoles", "value":"client,user"}]

```

The registrar should then create a JSON file as defined below for the user being registered.

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
# cd $COP/bin
# ./cop client register ../testdata/registerrequest.json http://localhost:8888
```

### LDAP

The COP server can be configured to read from an LDAP server.

In particular, the COP server may connect to an LDAP server to do the following:

   * authenticate a user prior to enrollment, and   
   * retrieve a user's attribute values which is used for authorization.

In order to configure the COP server to connect to an LDAP server, add a section of the following form to your COP server's configuration file:

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
   * `filter` is a filter to use when searching to convert a login user name to a distinquished name.  For example, a value of `(uid=%s)` searches for LDAP entries with the value of a `uid` attribute whose value is the login user name.  Similarly, `(email=%s)` may be used to login with an email address.

The following is a sample configuration section for the default settings for the OpenLDAP server whose docker image is at `https://github.com/osixia/docker-openldap`.

```
 "ldap": {
    "url": "ldap://cn=admin,dc=example,dc=org:admin@localhost:10389/dc=example,dc=org",
    "userfilter": "(uid=%s)"
 },
```

See `COP/testdata/testconfig-ldap.json` for the complete configuration file with this section.  Also see `COP/scripts/run-ldap-tests` for a script which starts an OpenLDAP docker image, configures it, runs the LDAP tests in COP/cli/server/ldap/ldap_test.go, and stops the OpenLDAP server.

##### When LDAP is configured, enrollment works as follows:

  * A COP client or client SDK sends an enrollment request with a basic authorization header.  
  * The COP server receives the enrollment request, decodes the user/pass in the authorization header, looks up the DN (Distinquished Name) associated with the user using the "userfilter" from the configuration file, and then attempts an LDAP bind with the user's password. If successful, the enrollment processing is authorized and can proceed.

##### When LDAP is configured, attribute retrieval works as follows:

   * A client SDK sends a request for a batch of tcerts *with one or more attributes*to the COP server.  
   * The COP server receives the tcert request and does as follows: 
       * extracts the enrollment ID from the token in the authorization header (after validating the token);
       * does an LDAP search/query to the LDAP server, requesting all of the attribute names received in the tcert request;
       * the attribute values are placed in the tcert as normal


### Setting up a cluster

Set up a proxy server. Haproxy is used in this example. Below is a basic configuration file that can be used to get haproxy up and running. Change hostname and port to reflect the settings of your COP servers.

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
      bind *:8888
      balance roundrobin
      server server1 <hostname:port>
      server server2 <hostname:port>
      server server3 <hostname:port>
```

#### Postgres

When starting up the COP servers specify the database that you would like to connect to. In your COP configuration file, the following should be present for a Postgres database:

cop.json
```
...
"driver":"postgres",
"data_source":"host=localhost port=5432 user=Username password=Password dbname=cop sslmode=disable",
...
```

Change "host" and "dbname" to reflect where your database is located and the database you would like to connect to. Default port is used if none is specified. Enter username and password for a user that has permission to connect to the database.

Once your proxy, COP servers, and Postgres server are all running you can have your client direct traffic to the proxy server which will load balance and direct traffic to the appropriate COP server which will read/write from the Postgres database.  

#### MySQL

When starting up the COP servers specify the database that you would like to connect to. In your COP configuration file, the following should be present for a Postgres database:

cop.json
```
...
"driver":"mysql",
"data_source":"root:root@tcp(localhost:3306)/cop?parseTime=true",
...
```

Change the host to reflect where your database is located. The database is specified after the '/', specify the database you would like to connect to. Default port is used if none is specified.

Once your proxy, COP servers, and database servers are all running you can have your clients direct traffic to the proxy server which will load balance and direct traffic to the appropriate COP server which will read/write from the database.  

### Run the cop tests

To run the COP test, do the following.

WARNING: You must first stop the COP server which you started above; otherwise, it will fail with a port binding error.

```
# cd $COP
# make tests
```
