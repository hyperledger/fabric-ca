Fabric CA User's Guide
======================

The Hyperledger Fabric CA is a Certificate Authority (CA)
for Hyperledger Fabric.

It provides features such as:

  * registration of identities, or connects to LDAP as the user
    registry
  * issuance of Enrollment Certificates (ECerts)
  * issuance of Transaction Certificates (TCerts), providing both
    anonymity and unlinkability when transacting on a Hyperledger Fabric
    blockchain
  * certificate renewal and revocation

Hyperledger Fabric CA consists of both a server and a client component as
described later in this document.

For developers interested in contributing to Hyperledger Fabric CA, see the
`Fabric CA repository <https://github.com/hyperledger/fabric-ca>`__ for more
information.


.. _Back to Top:

Table of Contents
-----------------

1. `Overview`_

2. `Getting Started`_

   1. `Prerequisites`_
   2. `Install`_
   3. `Explore the Fabric CA CLI`_

3. `File Formats`_

   1. `Fabric CA server's configuration file format`_
   2. `Fabric CA client's configuration file format`_

4. `Configuration Settings Precedence`_

5. `Fabric CA Server`_

   1. `Initializing the server`_
   2. `Starting the server`_
   3. `Configuring the database`_
   4. `Configuring LDAP`_
   5. `Setting up a cluster`_
   6. `Setting up multiple CAs`_
   7. `Enrolling an intermediate CA`_

6. `Fabric CA Client`_

   1. `Enrolling the bootstrap identity`_
   2. `Registering a new identity`_
   3. `Enrolling a peer identity`_
   4. `Reenrolling an identity`_
   5. `Revoking a certificate or identity`_
   6. `Enabling TLS`_
   7. `Contact specific CA instance`_

Overview
--------

The diagram below illustrates how the Hyperledger Fabric CA server fits into the
overall Hyperledger Fabric architecture.

.. image:: ./images/fabric-ca.png

There are two ways of interacting with a Hyperledger Fabric CA server:
via the Hyperledger Fabric CA client or through one of the Fabric SDKs.
All communication to the Hyperledger Fabric CA server is via REST APIs.
See `fabric-ca/swagger/swagger-fabric-ca.json` for the swagger documentation
for these REST APIs.

The Hyperledger Fabric CA client or SDK may connect to a server in a cluster
of Hyperledger Fabric CA servers.   This is illustrated in the top right section
of the diagram. The client routes to an HA Proxy endpoint which load balances
traffic to one of the fabric-ca-server cluster members.

All Hyperledger Fabric CA servers in a cluster share the same database for
keeping track of identities and certificates.  If LDAP is configured, the identity
information is kept in LDAP rather than the database.

A server may contain multiple CAs.  Each CA is either a root CA or an
intermediate CA.  Each intermediate CA has a parent CA which is either a
root CA or another intermediate CA.

Getting Started
---------------

Prerequisites
~~~~~~~~~~~~~~~

-  Go 1.7.x installation
-  ``GOPATH`` environment variable is set correctly
- libtool and libtdhl-dev packages are installed

The following installs the libtool dependencies on Ubuntu:

.. code:: bash

   sudo apt install libtool libltdl-dev

The following installs the libtool dependencies on MacOSX:

.. code:: bash

   brew install libtool

.. note:: libtldl-dev is not necessary on MacOSX if you instal
          libtool via Homebrew

For more information on libtool, see https://www.gnu.org/software/libtool.

For more information on libltdl-dev, see https://www.gnu.org/software/libtool/manual/html_node/Using-libltdl.html.

Install
~~~~~~~

The following installs both the `fabric-ca-server` and `fabric-ca-client` binaries
in $GOPATH/bin.

.. code:: bash

    go get -u github.com/hyperledger/fabric-ca/cmd/...

Note: If you have already cloned the fabric-ca repository, make sure you are on the
master branch before running the 'go get' command above. Otherwise, you might see the
following error:

::

    <gopath>/src/github.com/hyperledger/fabric-ca; git pull --ff-only
    There is no tracking information for the current branch.
    Please specify which branch you want to merge with.
    See git-pull(1) for details.

        git pull <remote> <branch>

    If you wish to set tracking information for this branch you can do so with:

        git branch --set-upstream-to=<remote>/<branch> tlsdoc

    package github.com/hyperledger/fabric-ca/cmd/fabric-ca-client: exit status 1

Start Server Natively
~~~~~~~~~~~~~~~~~~~~~

The following starts the `fabric-ca-server` with default settings.

.. code:: bash

    fabric-ca-server start -b admin:adminpw

The `-b` option provides the enrollment ID and secret for a bootstrap
administrator; this is required if LDAP is not enabled with the "ldap.enabled"
setting.

A default configuration file named `fabric-ca-server-config.yaml`
is created in the local directory which can be customized.

Start Server via Docker
~~~~~~~~~~~~~~~~~~~~~~~

Docker Hub
^^^^^^^^^^^^

Go to: https://hub.docker.com/r/hyperledger/fabric-ca/tags/

Find the tag that matches the architecture and version of fabric-ca
that you want to pull.

Navigate to `$GOPATH/src/github.com/hyperledger/fabric-ca/docker/server`
and open up docker-compose.yml in an editor.

Change the `image` line to reflect the tag you found previously. The file
may look like this for an x86 architecture for version beta.

.. code:: yaml

    fabric-ca-server:
      image: hyperledger/fabric-ca:x86_64-1.0.0-beta
      container_name: fabric-ca-server
      ports:
        - "7054:7054"
      environment:
        - FABRIC_CA_HOME=/etc/hyperledger/fabric-ca-server
      volumes:
        - "./fabric-ca-server:/etc/hyperledger/fabric-ca-server"
      command: sh -c 'fabric-ca-server start -b admin:adminpw'

Open up a terminal in the same directory as the docker-compose.yml file
and execute the following:

.. code:: bash

    # docker-compose up -d

This will pull down the specified fabric-ca image in the compose file
if it does not already exist, and start an instance of the fabric-ca
server.

Building Your Own Docker image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can build and start the server via docker-compose as shown below.

.. code:: bash

    cd $GOPATH/src/github.com/hyperledger/fabric-ca
    make docker
    cd docker/server
    docker-compose up -d

The hyperledger/fabric-ca docker image contains both the fabric-ca-server and
the fabric-ca-client.

.. code:: bash

    # cd $GOPATH/src/github.com/hyperledger/fabric-ca
    # FABRIC_CA_DYNAMIC_LINK=true make docker
    # cd docker/server
    # docker-compose up -d

Explore the Fabric CA CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section simply provides the usage messages for the Fabric CA server and client
for convenience.  Additional usage information is provided in following sections.

The following shows the Fabric CA server usage message.

.. code:: bash

    fabric-ca-server --help
    Hyperledger Fabric Certificate Authority Server

    Usage:
      fabric-ca-server [command]

    Available Commands:
      init        Initialize the Fabric CA server
      start       Start the Fabric CA server

    Flags:
      --address string                            Listening address of fabric-ca-server (default "0.0.0.0")
  -b, --boot string                               The user:pass for bootstrap admin which is required to build default config file
      --ca.certfile string                        PEM-encoded CA certificate file (default "ca-cert.pem")
      --ca.chainfile string                       PEM-encoded CA chain file (default "ca-chain.pem")
      --ca.keyfile string                         PEM-encoded CA key file (default "ca-key.pem")
  -n, --ca.name string                            Certificate Authority name
      --cacount int                               Number of non-default CA instances
      --cafiles stringSlice                       A list of comma-separated CA configuration files
  -c, --config string                             Configuration file (default "fabric-ca-server-config.yaml")
      --crlsizelimit int                          Size limit of an acceptable CRL in bytes (default 512000)
      --csr.cn string                             The common name field of the certificate signing request to a parent fabric-ca-server
      --csr.hosts stringSlice                     A list of comma-separated host names in a certificate signing request to a parent fabric-ca-server
      --db.datasource string                      Data source which is database specific (default "fabric-ca-server.db")
      --db.tls.certfiles stringSlice              A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)
      --db.tls.client.certfile string             PEM-encoded certificate file when mutual authenticate is enabled
      --db.tls.client.keyfile string              PEM-encoded key file when mutual authentication is enabled
      --db.type string                            Type of database; one of: sqlite3, postgres, mysql (default "sqlite3")
  -d, --debug                                     Enable debug level logging
      --intermediate.enrollment.label string      Label to use in HSM operations
      --intermediate.enrollment.profile string    Name of the signing profile to use in issuing the certificate
      --intermediate.parentserver.caname string   Name of the CA to connect to on fabric-ca-serve
  -u, --intermediate.parentserver.url string      URL of the parent fabric-ca-server (e.g. http://<username>:<password>@<address>:<port)
      --intermediate.tls.certfiles stringSlice    A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)
      --intermediate.tls.client.certfile string   PEM-encoded certificate file when mutual authenticate is enabled
      --intermediate.tls.client.keyfile string    PEM-encoded key file when mutual authentication is enabled
      --ldap.enabled                              Enable the LDAP client for authentication and attributes
      --ldap.groupfilter string                   The LDAP group filter for a single affiliation group (default "(memberUid=%s)")
      --ldap.tls.certfiles stringSlice            A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)
      --ldap.tls.client.certfile string           PEM-encoded certificate file when mutual authenticate is enabled
      --ldap.tls.client.keyfile string            PEM-encoded key file when mutual authentication is enabled
      --ldap.url string                           LDAP client URL of form ldap://adminDN:adminPassword@host[:port]/base
      --ldap.userfilter string                    The LDAP user filter to use when searching for users (default "(uid=%s)")
  -p, --port int                                  Listening port of fabric-ca-server (default 7054)
      --registry.maxenrollments int               Maximum number of enrollments; valid if LDAP not enabled
      --tls.certfile string                       PEM-encoded TLS certificate file for server's listening port (default "ca-cert.pem")
      --tls.clientauth.certfiles stringSlice      A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)
      --tls.clientauth.type string                Policy the server will follow for TLS Client Authentication. (default "noclientcert")
      --tls.enabled                               Enable TLS on the listening port
      --tls.keyfile string                        PEM-encoded TLS key for server's listening port (default "ca-key.pem")

    Use "fabric-ca-server [command] --help" for more information about a command.

The following shows the Fabric CA client usage message:

.. code:: bash

    fabric-ca-client --help
    Hyperledger Fabric Certificate Authority Client

    Usage:
      fabric-ca-client [command]

    Available Commands:
      enroll      Enroll an identity
      getcacert   Get CA certificate chain
      reenroll    Reenroll an identity
      register    Register an identity
      revoke      Revoke an identity

    Flags:
      --caname string                Name of CA
  -c, --config string                Configuration file (default "/Users/saadkarim/.fabric-ca-client/fabric-ca-client-config.yaml")
      --csr.hosts stringSlice        A list of comma-separated host names in a certificate signing request
      --csr.serialnumber string      The serial number in a certificate signing request, which becomes part of the DN (Distinquished Name)
  -d, --debug                        Enable debug level logging
      --enrollment.label string      Label to use in HSM operations
      --enrollment.profile string    Name of the signing profile to use in issuing the certificate
      --id.affiliation string        The identity's affiliation
      --id.attrs stringSlice         A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)
      --id.maxenrollments int        The maximum number of times the secret can be reused to enroll.
      --id.name string               Unique name of the identity
      --id.secret string             The enrollment secret for the identity being registered
      --id.type string               Type of identity being registered (e.g. 'peer, app, user')
  -M, --mspdir string                Membership Service Provider directory (default "msp")
  -m, --myhost string                Hostname to include in the certificate signing request during enrollment (default "saads-mbp.raleigh.ibm.com")
  -a, --revoke.aki string            AKI (Authority Key Identifier) of the certificate to be revoked
  -e, --revoke.name string           Identity whose certificates should be revoked
  -r, --revoke.reason string         Reason for revocation
  -s, --revoke.serial string         Serial number of the certificate to be revoked
      --tls.certfiles stringSlice    A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)
      --tls.client.certfile string   PEM-encoded certificate file when mutual authenticate is enabled
      --tls.client.keyfile string    PEM-encoded key file when mutual authentication is enabled
  -u, --url string                   URL of fabric-ca-server (default "http://localhost:7054")

    Use "fabric-ca-client [command] --help" for more information about a command.

.. note:: Note that command line options that are string slices (lists) can be
          specified either by specifying the option with comma-separated list
          elements or by specifying the option multiple times, each with a
          string value that make up the list. For example, to specify
          ``host1`` and ``host2`` for the ``csr.hosts`` option, you can either
          pass ``--csr.hosts 'host1,host2'`` or
          ``--csr.hosts host1 --csr.hosts host2``. When using the former format,
          please make sure there are no space before or after any commas.

`Back to Top`_

File Formats
------------

Fabric CA server's configuration file format
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A default configuration file (like the one shown below) is created in
the server's home directory (see `Fabric CA Server <#server>`__ section more info).

.. code:: yaml

    # Server's listening port (default: 7054)
    port: 7054

    # Enables debug logging (default: false)
    debug: false

    # Size limit of an acceptable CRL in bytes (default: 512000)
    crlsizelimit: 512000

    #############################################################################
    #  TLS section for the server's listening port
    #
    #  The following types are supported for client authentication: NoClientCert,
    #  RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven,
    #  and RequireAndVerifyClientCert.
    #
    #  Certfiles is a list of root certificate authorities that the server uses
    #  when verifying client certificates.
    #############################################################################
    tls:
      # Enable TLS (default: false)
      enabled: false
      # TLS for the server's listening port
      certfile: ca-cert.pem
      keyfile: ca-key.pem
      clientauth:
        type: noclientcert
        certfiles:

    #############################################################################
    #  The CA section contains information related to the Certificate Authority
    #  including the name of the CA, which should be unique for all members
    #  of a blockchain network.  It also includes the key and certificate files
    #  used when issuing enrollment certificates (ECerts) and transaction
    #  certificates (TCerts).
    #  The chainfile (if it exists) contains the certificate chain which
    #  should be trusted for this CA, where the 1st in the chain is always the
    #  root CA certificate.
    #############################################################################
    ca:
      # Name of this CA
      name:
      # Key file (default: ca-key.pem)
      keyfile: ca-key.pem
      # Certificate file (default: ca-cert.pem)
      certfile: ca-cert.pem
      # Chain file (default: chain-cert.pem)
      chainfile: ca-chain.pem

    #############################################################################
    #  The registry section controls how the fabric-ca-server does two things:
    #  1) authenticates enrollment requests which contain a username and password
    #     (also known as an enrollment ID and secret).
    #  2) once authenticated, retrieves the identity's attribute names and
    #     values which the fabric-ca-server optionally puts into TCerts
    #     which it issues for transacting on the Hyperledger Fabric blockchain.
    #     These attributes are useful for making access control decisions in
    #     chaincode.
    #  There are two main configuration options:
    #  1) The fabric-ca-server is the registry
    #  2) An LDAP server is the registry, in which case the fabric-ca-server
    #     calls the LDAP server to perform these tasks.
    #############################################################################
    registry:
      # Maximum number of times a password/secret can be reused for enrollment
      # (default: -1, which means there is no limit)
      maxenrollments: -1

      # Contains identity information which is used when LDAP is disabled
      identities:
         - name: <<<ADMIN>>>
           pass: <<<ADMINPW>>>
           type: client
           affiliation: ""
           maxenrollments: -1
           attrs:
              hf.Registrar.Roles: "client,user,peer,validator,auditor"
              hf.Registrar.DelegateRoles: "client,user,validator,auditor"
              hf.Revoker: true
              hf.IntermediateCA: true

    #############################################################################
    #  Database section
    #  Supported types are: "sqlite3", "postgres", and "mysql".
    #  The datasource value depends on the type.
    #  If the type is "sqlite3", the datasource value is a file name to use
    #  as the database store.  Since "sqlite3" is an embedded database, it
    #  may not be used if you want to run the fabric-ca-server in a cluster.
    #  To run the fabric-ca-server in a cluster, you must choose "postgres"
    #  or "mysql".
    #############################################################################
    db:
      type: sqlite3
      datasource: fabric-ca-server.db
      tls:
          enabled: false
          certfiles:
            - db-server-cert.pem
          client:
            certfile: db-client-cert.pem
            keyfile: db-client-key.pem

    #############################################################################
    #  LDAP section
    #  If LDAP is enabled, the fabric-ca-server calls LDAP to:
    #  1) authenticate enrollment ID and secret (i.e. username and password)
    #     for enrollment requests;
    #  2) To retrieve identity attributes
    #############################################################################
    ldap:
       # Enables or disables the LDAP client (default: false)
       enabled: false
       # The URL of the LDAP server
       url: ldap://<adminDN>:<adminPassword>@<host>:<port>/<base>
       tls:
          certfiles:
            - ldap-server-cert.pem
          client:
             certfile: ldap-client-cert.pem
             keyfile: ldap-client-key.pem

    #############################################################################
    #  Affiliation section
    #############################################################################
    affiliations:
       org1:
          - department1
          - department2
       org2:
          - department1

    #############################################################################
    #  Signing section
    #
    #  The "default" subsection is used to sign enrollment certificates;
    #  the default expiration ("expiry" field) is "8760h", which is 1 year in hours.
    #
    #  The "ca" profile subsection is used to sign intermediate CA certificates;
    #  the default expiration ("expiry" field) is "43800h" which is 5 years in hours.
    #  Note that "isca" is true, meaning that it issues a CA certificate.
    #  A maxpathlen of 0 means that the intermediate CA cannot issue other
    #  intermediate CA certificates, though it can still issue end entity certificates.
    #  (See RFC 5280, section 4.2.1.9)
    #############################################################################
    signing:
        default:
          usage:
            - cert sign
          expiry: 8760h
        profiles:
          ca:
             usage:
               - cert sign
             expiry: 43800h
             caconstraint:
               isca: true
               maxpathlen: 0

    ###########################################################################
    #  Certificate Signing Request (CSR) section.
    #  This controls the creation of the root CA certificate.
    #  The expiration for the root CA certificate is configured with the
    #  "ca.expiry" field below, whose default value is "131400h" which is
    #  15 years in hours.
    #  The pathlength field is used to limit CA certificate hierarchy as described
    #  in section 4.2.1.9 of RFC 5280.
    #  Examples:
    #  1) No pathlength value means no limit is requested.
    #  2) pathlength == 1 means a limit of 1 is requested which is the default for
    #     a root CA.  This means the root CA can issue intermediate CA certificates,
    #     but these intermediate CAs may not in turn issue other CA certificates
    #     though they can still issue end entity certificates.
    #  3) pathlength == 0 means a limit of 0 is requested;
    #     this is the default for an intermediate CA, which means it can not issue
    #     CA certificates though it can still issue end entity certificates.
    ###########################################################################
    csr:
       cn: <<<COMMONNAME>>>
       names:
          - C: US
            ST: "North Carolina"
            L:
            O: Hyperledger
            OU: Fabric
       hosts:
         - <<<MYHOST>>>
         - localhost
       ca:
          expiry: 131400h
          pathlength: <<<PATHLENGTH>>>

    #############################################################################
    # BCCSP (BlockChain Crypto Service Provider) section is used to select which
    # crypto library implementation to use
    #############################################################################
    bccsp:
        default: SW
        sw:
            hash: SHA2
            security: 256
            filekeystore:
                # The directory used for the software file-based keystore
                keystore: msp/keystore

    #############################################################################
    # Multi CA section
    #
    # Each Fabric CA server contains one CA by default.  This section is used
    # to configure multiple CAs in a single server.
    #
    # 1) --cacount <number-of-CAs>
    # Automatically generate <number-of-CAs> non-default CAs.  The names of these
    # additional CAs are "ca1", "ca2", ... "caN", where "N" is <number-of-CAs>
    # This is particularly useful in a development environment to quickly set up
    # multiple CAs.
    #
    # 2) --cafiles <CA-config-files>
    # For each CA config file in the list, generate a separate signing CA.  Each CA
    # config file in this list MAY contain all of the same elements as are found in
    # the server config file except port, debug, and tls sections.
    #
    # Examples:
    # fabric-ca-server start -b admin:adminpw --cacount 2
    #
    # fabric-ca-server start -b admin:adminpw --cafiles ca/ca1/fabric-ca-server-config.yaml
    # --cafiles ca/ca2/fabric-ca-server-config.yaml
    #
    #############################################################################

    cacount:

    cafiles:

    #############################################################################
    # Intermediate CA section
    #
    # The relationship between servers and CAs is as follows:
    #   1) A single server process may contain or function as one or more CAs.
    #      This is configured by the "Multi CA section" above.
    #   2) Each CA is either a root CA or an intermediate CA.
    #   3) Each intermediate CA has a parent CA which is either a root CA or another intermediate CA.
    #
    # This section pertains to configuration of #2 and #3.
    # If the "intermediate.parentserver.url" property is set,
    # then this is an intermediate CA with the specified parent
    # CA.
    #
    # parentserver section
    #    url - The URL of the parent server
    #    caname - Name of the CA to enroll within the server
    #
    # enrollment section used to enroll intermediate CA with parent CA
    #    profile - Name of the signing profile to use in issuing the certificate
    #    label - Label to use in HSM operations
    #
    # tls section for secure socket connection
    #   certfiles - PEM-encoded list of trusted root certificate files
    #   client:
    #     certfile - PEM-encoded certificate file for when client authentication
    #     is enabled on server
    #     keyfile - PEM-encoded key file for when client authentication
    #     is enabled on server
    #############################################################################
    intermediate:
      parentserver:
        url:
        caname:

      enrollment:
        hosts:
        profile:
        label:

      tls:
        certfiles:
        client:
          certfile:
          keyfile:

Fabric CA client's configuration file format
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A default configuration file (like the one shown below) is created in
the client's home directory (see `Fabric CA Client <#client>`__ section more info).

.. code:: yaml

    #############################################################################
    # Client Configuration
    #############################################################################

    # URL of the Fabric CA server (default: http://localhost:7054)
    URL: http://localhost:7054

    # Membership Service Provider (MSP) directory
    # When the client is used to enroll a peer or an orderer, this field must be
    # set to the MSP directory of the peer/orderer
    MSPDir:

    #############################################################################
    #    TLS section for secure socket connection
    #############################################################################
    tls:
      # Enable TLS (default: false)
      enabled: false
      certfiles:
      client:
        certfile:
        keyfile:

    #############################################################################
    #  Certificate Signing Request section for generating the CSR for
    #  an enrollment certificate (ECert)
    #############################################################################
    csr:
      cn: <<<ENROLLMENT_ID>>>
      names:
        - C: US
          ST: North Carolina
          L:
          O: Hyperledger
          OU: Fabric
      hosts:
       - <<<MYHOST>>>
      ca:
        pathlen:
        pathlenzero:
        expiry:

    #############################################################################
    #  Registration section used to register a new identity with Fabric CA server
    #############################################################################
    id:
      name:
      type:
      affiliation:
      attributes:
        - name:
          value:

    #############################################################################
    #  Enrollment section used to enroll an identity with Fabric CA server
    #############################################################################
    enrollment:
      profile:
      label:

    # Name of the CA to connect to within the fabric-ca server
    caname:

`Back to Top`_

Configuration Settings Precedence
---------------------------------

The Fabric CA provides 3 ways to configure settings on the Fabric CA server
and client. The precedence order is:

  1. CLI flags
  2. Environment variables
  3. Configuration file

In the remainder of this document, we refer to making changes to
configuration files. However, configuration file changes can be
overridden through environment variables or CLI flags.

For example, if we have the following in the client configuration file:

.. code:: yaml

    tls:
      # Enable TLS (default: false)
      enabled: false

      # TLS for the client's listenting port (default: false)
      certfiles:
      client:
        certfile: cert.pem
        keyfile:

The following environment variable may be used to override the ``cert.pem``
setting in the configuration file:

.. code:: bash

  export FABRIC_CA_CLIENT_TLS_CLIENT_CERTFILE=cert2.pem

If we wanted to override both the environment variable and configuration
file, we can use a command line flag.

.. code:: bash

  fabric-ca-client enroll --tls.client.certfile cert3.pem

The same approach applies to fabric-ca-server, except instead of using
``FABIRC_CA_CLIENT`` as the prefix to environment variables,
``FABRIC_CA_SERVER`` is used.

.. _server:


A word on file paths
--------------------
All the properties in the Fabric CA server and client configuration file
that specify file names support both relative and absolute paths.
Relative paths are relative to the config directory, where the
configuration file is located. For example, if the config directory is
``~/config`` and the tls section is as shown below, the Fabric CA server
or client will look for the ``root.pem`` file in the ``~/config``
directory, ``cert.pem`` file in the ``~/config/certs`` directory and the
``key.pem`` file in the ``/abs/path`` directory

.. code:: yaml

    tls:
      enabled: true
      certfiles:
        - root.pem
      client:
        certfile: certs/cert.pem
        keyfile: /abs/path/key.pem



Fabric CA Server
----------------

This section describes the Fabric CA server.

You may initialize the Fabric CA server before starting it. This provides an
opportunity for you to generate a default configuration file that can be
reviewed and customized before starting the server.

The Fabric CA server's home directory is determined as follows:
  - if the ``FABRIC_CA_SERVER_HOME`` environment variable is set, use
    its value
  - otherwise, if ``FABRIC_CA_HOME`` environment variable is set, use
    its value
  - otherwise, if the ``CA_CFG_PATH`` environment variable is set, use
    its value
  - otherwise, use current working directory

For the remainder of this server section, we assume that you have set
the ``FABRIC_CA_HOME`` environment variable to
``$HOME/fabric-ca/server``.

The instructions below assume that the server configuration file exists
in the server's home directory.

.. _initialize:

Initializing the server
~~~~~~~~~~~~~~~~~~~~~~~

Initialize the Fabric CA server as follows:

.. code:: bash

    fabric-ca-server init -b admin:adminpw

The ``-b`` (bootstrap identity) option is required for initialization when
LDAP is disabled. At least one bootstrap identity is required to start the
Fabric CA server; this identity is the server administrator.

The server configuration file contains a Certificate Signing Request (CSR)
section that can be configured. The following is a sample CSR.

.. _csr-fields:

.. code:: yaml

   cn: fabric-ca-server
   names:
      - C: US
        ST: "North Carolina"
        L:
        O: Hyperledger
        OU: Fabric
   hosts:
     - host1.example.com
     - localhost
   ca:
      expiry: 131400h
      pathlength: 1

All of the fields above pertain to the X.509 signing key and certificate which
is generated by the ``fabric-ca-server init``.  This corresponds to the
``ca.certfile`` and ``ca.keyfile`` files in the server's configuration file.
The fields are as follows:

  -  **cn** is the Common Name
  -  **O** is the organization name
  -  **OU** is the organizational unit
  -  **L** is the location or city
  -  **ST** is the state
  -  **C** is the country

If custom values for the CSR are required, you may customize the configuration
file, delete the files specified by the ``ca.certfile`` and ``ca-keyfile``
configuration items, and then run the ``fabric-ca-server init -b admin:adminpw``
command again.

The ``fabric-ca-server init`` command generates a self-signed CA certificate
unless the ``-u <parent-fabric-ca-server-URL>`` option is specified.
If the ``-u`` is specified, the server's CA certificate is signed by the
parent Fabric CA server.
In order to authenticate to the parent Fabric CA server, the URL must
be of the form ``<scheme>://<enrollmentID>:<secret>@<host>:<port>``, where
<enrollmentID> and <secret> correspond to an identity with an 'hf.IntermediateCA'
attribute whose value equals 'true'.
The ``fabric-ca-server init`` command also generates a default configuration
file named **fabric-ca-server-config.yaml** in the server's home directory.

If you want the Fabric CA server to use a CA signing certificate and key file which you provide,
you must place your files in the location referenced by ``ca.certfile`` and ``ca.keyfile`` respectively.
Both files must be PEM-encoded and must not be encrypted.
More specifically, the contents of the CA certificate file must begin with ``-----BEGIN CERTIFICATE-----``
and the contents of the key file must begin with ``-----BEGIN PRIVATE KEY-----`` and not
``-----BEGIN ENCRYPTED PRIVATE KEY-----``.

Algorithms and key sizes

The CSR can be customized to generate X.509 certificates and keys that
support Elliptic Curve (ECDSA). The following setting is an
example of the implementation of Elliptic Curve Digital Signature
Algorithm (ECDSA) with curve ``prime256v1`` and signature algorithm
``ecdsa-with-SHA256``:

.. code:: yaml

    key:
       algo: ecdsa
       size: 256

The choice of algorithm and key size are based on security needs.

Elliptic Curve (ECDSA) offers the following key size options:

+--------+--------------+-----------------------+
| size   | ASN1 OID     | Signature Algorithm   |
+========+==============+=======================+
| 256    | prime256v1   | ecdsa-with-SHA256     |
+--------+--------------+-----------------------+
| 384    | secp384r1    | ecdsa-with-SHA384     |
+--------+--------------+-----------------------+
| 521    | secp521r1    | ecdsa-with-SHA512     |
+--------+--------------+-----------------------+

Starting the server
~~~~~~~~~~~~~~~~~~~

Start the Fabric CA server as follows:

.. code:: bash

    fabric-ca-server start -b <admin>:<adminpw>

If the server has not been previously initialized, it will initialize
itself as it starts for the first time.  During this initialization, the
server will generate the ca-cert.pem and ca-key.pem files if they don't
yet exist and will also create a default configuration file if it does
not exist.  See the `Initialize the Fabric CA server <#initialize>`__ section.

Unless the Fabric CA server is configured to use LDAP, it must be
configured with at least one pre-registered bootstrap identity to enable you
to register and enroll other identities. The ``-b`` option specifies the
name and password for a bootstrap identity.

To cause the Fabric CA server to listen on ``https`` rather than
``http``, set ``tls.enabled`` to ``true``.

To limit the number of times that the same secret (or password) can be
used for enrollment, set the ``registry.maxenrollments`` in the configuration
file to the appropriate value. If you set the value to 1, the Fabric CA
server allows passwords to only be used once for a particular enrollment
ID. If you set the value to -1, the Fabric CA server places no limit on
the number of times that a secret can be reused for enrollment. The
default value is -1. Setting the value to 0, the Fabric CA server will
disable enrollment for all identitiies and registeration of identities will
not be allowed.

The Fabric CA server should now be listening on port 7054.

You may skip to the `Fabric CA Client <#fabric-ca-client>`__ section if
you do not want to configure the Fabric CA server to run in a cluster or
to use LDAP.

Configuring the database
~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to configure the Fabric CA server to connect
to PostgreSQL or MySQL databases. The default database is SQLite and the
default database file is ``fabric-ca-server.db`` in the Fabric CA
server's home directory.

If you don't care about running the Fabric CA server in a cluster, you
may skip this section; otherwise, you must configure either PostgreSQL or
MySQL as described below. Fabric CA supports the following database
versions in a cluster setup:

- PostgreSQL: 9.5.5 or later
- MySQL: 5.17.16 or later

PostgreSQL
^^^^^^^^^^

The following sample may be added to the server's configuration file in
order to connect to a PostgreSQL database. Be sure to customize the
various values appropriately. There are limitations on what characters are allowed
in the database name. Please refer to the following Postgres documentation
for more information: https://www.postgresql.org/docs/current/static/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS

.. code:: yaml

    db:
      type: postgres
      datasource: host=localhost port=5432 user=Username password=Password dbname=fabric_ca sslmode=verify-full

Specifying *sslmode* configures the type of SSL authentication. Valid
values for sslmode are:

|

+----------------+----------------+
| Mode           | Description    |
+================+================+
| disable        | No SSL         |
+----------------+----------------+
| require        | Always SSL     |
|                | (skip          |
|                | verification)  |
+----------------+----------------+
| verify-ca      | Always SSL     |
|                | (verify that   |
|                | the            |
|                | certificate    |
|                | presented by   |
|                | the server was |
|                | signed by a    |
|                | trusted CA)    |
+----------------+----------------+
| verify-full    | Same as        |
|                | verify-ca AND  |
|                | verify that    |
|                | the            |
|                | certificate    |
|                | presented by   |
|                | the server was |
|                | signed by a    |
|                | trusted CA and |
|                | the server     |
|                | hostname       |
|                | matches the    |
|                | one in the     |
|                | certificate    |
+----------------+----------------+

|

If you would like to use TLS, then the ``db.tls`` section in the Fabric CA server
configuration file must be specified. If SSL client authentication is enabled
on the PostgreSQL server, then the client certificate and key file must also be
specified in the ``db.tls.client`` section. The following is an example
of the ``db.tls`` section:

.. code:: yaml

    db:
      ...
      tls:
          enabled: true
          certfiles:
            - db-server-cert.pem
          client:
                certfile: db-client-cert.pem
                keyfile: db-client-key.pem

| **certfiles** - A list of PEM-encoded trusted root certificate files.
| **certfile** and **keyfile** - PEM-encoded certificate and key files that are used by the Fabric CA server to communicate securely with the PostgreSQL server

PostgreSQL SSL Configuration
"""""""""""""""""""""""""""""

**Basic instructions for configuring SSL on the PostgreSQL server:**

1. In postgresql.conf, uncomment SSL and set to "on" (SSL=on)

2. Place certificate and key files in the PostgreSQL data directory.

Instructions for generating self-signed certificates for:
https://www.postgresql.org/docs/9.5/static/ssl-tcp.html

Note: Self-signed certificates are for testing purposes and should not
be used in a production environment

**PostgreSQL Server - Require Client Certificates**

1. Place certificates of the certificate authorities (CAs) you trust in the file root.crt in the PostgreSQL data directory

2. In postgresql.conf, set "ssl\_ca\_file" to point to the root cert of the client (CA cert)

3. Set the clientcert parameter to 1 on the appropriate hostssl line(s) in pg\_hba.conf.

For more details on configuring SSL on the PostgreSQL server, please refer
to the following PostgreSQL documentation:
https://www.postgresql.org/docs/9.4/static/libpq-ssl.html

MySQL
^^^^^^^

The following sample may be added to the Fabric CA server configuration file in
order to connect to a MySQL database. Be sure to customize the various
values appropriately. There are limitations on what characters are allowed
in the database name. Please refer to the following MySQL documentation
for more information: https://dev.mysql.com/doc/refman/5.7/en/identifiers.html

On MySQL 5.7.X, certain modes affect whether the server permits '0000-00-00' as a valid date.
It might be necessary to relax the modes that MySQL server uses. We want to allow
the server to be able to accept zero date values.

In my.cnf, find the configuration option *sql_mode* and remove *NO_ZERO_DATE* if present.
Restart MySQL server after making this change.

Please refer to the following MySQL documentation on different modes available
and select the appropriate settings for the specific version of MySQL that is
being used.

https://dev.mysql.com/doc/refman/5.7/en/sql-mode.html

On MySQL 5.7.X, certain modes affect whether the server permits '0000-00-00' as a valid date.
It might be necessary to relax the modes that MySQL server uses. We want to allow
the server to be able to accept zero date values.

In my.cnf, find the configuration option *sql_mode* and remove *NO_ZERO_DATE* if present.
Restart MySQL server after making this change.

Please refer to the following MySQL documentation on different modes available
and select the appropriate settings for the specific version of MySQL that is
being used.

https://dev.mysql.com/doc/refman/5.7/en/sql-mode.html

.. code:: yaml

    db:
      type: mysql
      datasource: root:rootpw@tcp(localhost:3306)/fabric_ca?parseTime=true&tls=custom

If connecting over TLS to the MySQL server, the ``db.tls.client``
section is also required as described in the **PostgreSQL** section above.

MySQL SSL Configuration
""""""""""""""""""""""""

**Basic instructions for configuring SSL on MySQL server:**

1. Open or create my.cnf file for the server. Add or uncomment the
   lines below in the [mysqld] section. These should point to the key and
   certificates for the server, and the root CA cert.

   Instructions on creating server and client-side certficates:
   http://dev.mysql.com/doc/refman/5.7/en/creating-ssl-files-using-openssl.html

   [mysqld] ssl-ca=ca-cert.pem ssl-cert=server-cert.pem ssl-key=server-key.pem

   Can run the following query to confirm SSL has been enabled.

   mysql> SHOW GLOBAL VARIABLES LIKE 'have\_%ssl';

   Should see:

   +----------------+----------------+
   | Variable_name  | Value          |
   +================+================+
   | have_openssl   | YES            |
   +----------------+----------------+
   | have_ssl       | YES            |
   +----------------+----------------+

2. After the server-side SSL configuration is finished, the next step is
   to create a user who has a privilege to access the MySQL server over
   SSL. For that, log in to the MySQL server, and type:

   mysql> GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%' IDENTIFIED BY
   'password' REQUIRE SSL; mysql> FLUSH PRIVILEGES;

   If you want to give a specific IP address from which the user will
   access the server change the '%' to the specific IP address.

**MySQL Server - Require Client Certificates**

Options for secure connections are similar to those used on the server side.

-  ssl-ca identifies the Certificate Authority (CA) certificate. This
   option, if used, must specify the same certificate used by the server.
-  ssl-cert identifies MySQL server's certificate.
-  ssl-key identifies MySQL server's private key.

Suppose that you want to connect using an account that has no special
encryption requirements or was created using a GRANT statement that
includes the REQUIRE SSL option. As a recommended set of
secure-connection options, start the MySQL server with at least
--ssl-cert and --ssl-key options. Then set the ``db.tls.certfiles`` property
in the server configuration file and start the Fabric CA server.

To require that a client certificate also be specified, create the
account using the REQUIRE X509 option. Then the client must also specify
proper client key and certificate files; otherwise, the MySQL server
will reject the connection. To specify client key and certificate files
for the Fabric CA server, set the ``db.tls.client.certfile``,
and ``db.tls.client.keyfile`` configuration properties.

Configuring LDAP
~~~~~~~~~~~~~~~~

The Fabric CA server can be configured to read from an LDAP server.

In particular, the Fabric CA server may connect to an LDAP server to do
the following:

-  authenticate an identity prior to enrollment
-  retrieve an identity's attribute values which are used for authorization.

Modify the LDAP section of the Fabric CA server's configuration file to configure the
server to connect to an LDAP server.

.. code:: yaml

    ldap:
       # Enables or disables the LDAP client (default: false)
       enabled: false
       # The URL of the LDAP server
       url: <scheme>://<adminDN>:<adminPassword>@<host>:<port>/<base>
       userfilter: filter

Where:

  * ``scheme`` is one of *ldap* or *ldaps*;
  * ``adminDN`` is the distinquished name of the admin user;
  * ``pass`` is the password of the admin user;
  * ``host`` is the hostname or IP address of the LDAP server;
  * ``port`` is the optional port number, where default 389 for *ldap*
    and 636 for *ldaps*;
  * ``base`` is the optional root of the LDAP tree to use for searches;
  * ``filter`` is a filter to use when searching to convert a login
    user name to a distinquished name. For example, a value of
    ``(uid=%s)`` searches for LDAP entries with the value of a ``uid``
    attribute whose value is the login user name. Similarly,
    ``(email=%s)`` may be used to login with an email address.

The following is a sample configuration section for the default settings
for the OpenLDAP server whose docker image is at
``https://github.com/osixia/docker-openldap``.

.. code:: yaml

    ldap:
       enabled: true
       url: ldap://cn=admin,dc=example,dc=org:admin@localhost:10389/dc=example,dc=org
       userfilter: (uid=%s)

See ``FABRIC_CA/scripts/run-ldap-tests`` for a script which starts an
OpenLDAP docker image, configures it, runs the LDAP tests in
``FABRIC_CA/cli/server/ldap/ldap_test.go``, and stops the OpenLDAP
server.

When LDAP is configured, enrollment works as follows:


-  The Fabric CA client or client SDK sends an enrollment request with a
   basic authorization header.
-  The Fabric CA server receives the enrollment request, decodes the
   identity name and password in the authorization header, looks up the DN (Distinquished
   Name) associated with the identity name using the "userfilter" from the
   configuration file, and then attempts an LDAP bind with the identity's
   password. If the LDAP bind is successful, the enrollment processing is
   authorized and can proceed.

When LDAP is configured, attribute retrieval works as follows:


-  A client SDK sends a request for a batch of tcerts **with one or more
   attributes** to the Fabric CA server.
-  The Fabric CA server receives the tcert request and does as follows:

   -  extracts the enrollment ID from the token in the authorization
      header (after validating the token);
   -  does an LDAP search/query to the LDAP server, requesting all of
      the attribute names received in the tcert request;
   -  the attribute values are placed in the tcert as normal.

Setting up a cluster
~~~~~~~~~~~~~~~~~~~~

You may use any IP sprayer to load balance to a cluster of Fabric CA
servers. This section provides an example of how to set up Haproxy to
route to a Fabric CA server cluster. Be sure to change hostname and port
to reflect the settings of your Fabric CA servers.

haproxy.conf

.. code::

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
          server server1 hostname1:port
          server server2 hostname2:port
          server server3 hostname3:port


Note: If using TLS, need to use ``mode tcp``.

Setting up multiple CAs
~~~~~~~~~~~~~~~~~~~~~~~

The fabric-ca server by default consists of a single default CA. However, additional CAs
can be added to a single server by using `cafiles` or `cacount` configuration options.
Each additional CA will have its own home directory.

cacount:
^^^^^^^^

The `cacount` provides a quick way to start X number of default additional
CAs. The home directory will be relative to the server directory. With this option,
the directory structure will be as follows:

.. code:: yaml

    --<Server Home>
      |--ca
        |--ca1
        |--ca2

Each additional CA will get a default configuration file generated in it's home
directory, within the configuration file it will contain a unique CA name.

For example, the following command will start 2 default CA instances:

.. code:: bash

    fabric-ca-server start -b admin:adminpw --cacount 2

cafiles:
^^^^^^^^

If absolute paths are not provided when using the cafiles configuration option,
the CA home directory will be relative to the server directory.

To use this option, CA configuration files must have already been generated and
configured for each CA that is to be started. Each configuration file must have
a unique CA name and Common Name (CN), otherwise the server will fail to start as these
names must be unique. The CA configuration files will override any default
CA configuration, and any missing options in the CA configuration files will be
replaced by the values from the default CA.

The precedence order will be as follows:

  1. CA Configuration file
  2. Default CA CLI flags
  3. Default CA Environment variables
  4. Default CA Configuration file

A CA configuration file must contain at least the following:

.. code:: yaml

    ca:
    # Name of this CA
    name: <CANAME>

    csr:
      cn: <COMMONNAME>

You may configure your directory structure as follows:

.. code:: yaml

    --<Server Home>
      |--ca
        |--ca1
          |-- fabric-ca-config.yaml
        |--ca2
          |-- fabric-ca-config.yaml

For example, the following command will start two customized CA instances:

.. code:: bash

    fabric-ca-server start -b admin:adminpw --cafiles ca/ca1/fabric-ca-config.yaml
    --cafiles ca/ca2/fabric-ca-config.yaml

Enrolling an intermediate CA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to create a CA signing certificate for an intermediate CA, the intermediate
CA must enroll with a parent CA in the same way that a fabric-ca-client enrolls with a CA.
This is done by using the -u option to specify the URL of the parent CA and the enrollment ID
and secret as shown below.  The identity associated with this enrollment ID must have an
attribute with a name of "hf.IntermediateCA" and a value of "true".  The CN (or Common Name)
of the issued certificate will be set to the enrollment ID. An error will occur if an intermediate
CA tries to explicitly specify a CN value.

.. code:: bash

    fabric-ca-server start -b admin:adminpw -u http://<enrollmentID>:<secret>@<parentserver>:<parentport>

For other intermediate CA flags see `Fabric CA server's configuration file format`_ section.

`Back to Top`_

.. _client:

Fabric CA Client
----------------

This section describes how to use the fabric-ca-client command.

The Fabric CA client's home directory is determined as follows:

  - if the ``FABRIC_CA_CLIENT_HOME`` environment variable is set, use
    its value
  - otherwise, if the ``FABRIC_CA_HOME`` environment variable is set,
    use its value
  - otherwise, if the ``CA_CFG_PATH`` environment variable is set, use
    its value
  - otherwise, use ``$HOME/.fabric-ca-client``


The instructions below assume that the client configuration file exists
in the client's home directory.

Enrolling the bootstrap identity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, if needed, customize the CSR (Certificate Signing Request) section
in the client configuration file. Note that ``csr.cn`` field must be set
to the ID of the bootstrap identity. Default CSR values are shown below:

.. code:: yaml

    csr:
      cn: <<enrollment ID>>
      key:
        algo: ecdsa
        size: 256
      names:
        - C: US
          ST: North Carolina
          L:
          O: Hyperledger Fabric
          OU: Fabric CA
      hosts:
       - <<hostname of the fabric-ca-client>>
      ca:
        pathlen:
        pathlenzero:
        expiry:

See `CSR fields <#csr-fields>`__ for description of the fields.

Then run ``fabric-ca-client enroll`` command to enroll the identity. For example,
following command enrolls an identity whose ID is **admin** and password is **adminpw**
by calling Fabric CA server that is running locally at 7054 port.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/admin
    fabric-ca-client enroll -u http://admin:adminpw@localhost:7054

The enroll command stores an enrollment certificate (ECert), corresponding private key and CA
certificate chain PEM files in the subdirectories of the Fabric CA client's ``msp`` directory.
You will see messages indicating where the PEM files are stored.

Registering a new identity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The identity performing the register request must be currently enrolled, and
must also have the proper authority to register the type of the identity that is being
registered.

In particular, two authorization checks are made by the Fabric CA server
during registration as follows:

 1. The invoker's identity must have the "hf.Registrar.Roles" attribute with a
    comma-separated list of values where one of the value equals the type of
    identity being registered; for example, if the invoker's identity has the
    "hf.Registrar.Roles" attribute with a value of "peer,app,user", the invoker can register identities of type peer, app, and user, but not orderer.

 2. The affiliation of the invoker's identity must be equal to or a prefix of
    the affiliation of the identity being registered.  For example, an invoker
    with an affiliation of "a.b" may register an identity with an affiliation
    of "a.b.c" but may not register an identity with an affiliation of "a.c".

The following command uses the **admin** identity's credentials to register a new
identity with an enrollment id of "admin2", a type of "user", an affiliation of
"org1.department1", an attribute named "hf.Revoker" with a value of "true", and
an attribute named "foo" with a value of "bar".

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/admin
    fabric-ca-client register --id.name admin2 --id.type user --id.affiliation org1.department1 --id.attrs 'hf.Revoker=true,foo=bar'

The password, also known as the enrollment secret, is printed.
This password is required to enroll the identity.
This allows an administrator to register an identity and give the
enrollment ID and the secret to someone else to enroll the identity.

Multiple attributes can be specified as part of the --id.attrs flag, each
attribute must be comma separated. For an attribute value that contains a comma,
the attribute must be encapsulated in double quotes. See example below.

.. code:: bash

    fabric-ca-client register -d --id.name admin2 --id.type user --id.affiliation org1.department1 --id.attrs '"hf.Registrar.Roles=peer,user",hf.Revoker=true'

or

.. code:: bash

    fabric-ca-client register -d --id.name admin2 --id.type user --id.affiliation org1.department1 --id.attrs '"hf.Registrar.Roles=peer,user"' --id.attrs hf.Revoker=true

You may set default values for any of the fields used in the register command
by editing the client's configuration file.  For example, suppose the configuration
file contains the following:

.. code:: yaml

    id:
      name:
      type: user
      affiliation: org1.department1
      maxenrollments: -1
      attributes:
        - name: hf.Revoker
          value: true
        - name: anotherAttrName
          value: anotherAttrValue

The following command would then register a new identity with an enrollment id of
"admin3" which it takes from the command line, and the remainder is taken from the
configuration file including the identity type: "user", affiliation: "org1.department1",
and two attributes: "hf.Revoker" and "anotherAttrName".

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/admin
    fabric-ca-client register --id.name admin3

To register an identity with multiple attributes requires specifying all attribute names and values
in the configuration file as shown above.

Setting `maxenrollments` to 0 or leaving it out from the configuration will result in the identity
being registerd to use the CA's max enrollment value. Furthermore, the max enrollment value for
an identity being registered cannot exceed the CA's max enrollment value. For example, if the CA's
max enrollment value is 5. Any new identity must have a value less than or equal to 5, and also
can't set it to -1 (infinite enrollments).

Next, let's register a peer identity which will be used to enroll the peer in the following section.
The following command registers the **peer1** identity.  Note that we choose to specify our own
password (or secret) rather than letting the server generate one for us.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/admin
    fabric-ca-client register --id.name peer1 --id.type peer --id.affiliation org1.department1 --id.secret peer1pw

Enrolling a Peer Identity
~~~~~~~~~~~~~~~~~~~~~~~~~

Now that you have successfully registered a peer identity, you may now
enroll the peer given the enrollment ID and secret (i.e. the *password*
from the previous section).  This is similar to enrolling the bootstrap identity
except that we also demonstrate how to use the "-M" option to populate the
Hyperledger Fabric MSP (Membership Service Provider) directory structure.

The following command enrolls peer1.
Be sure to replace the value of the "-M" option with the path to your
peer's MSP directory which is the
'mspConfigPath' setting in the peer's core.yaml file.
You may also set the FABRIC_CA_CLIENT_HOME to the home directory of your peer.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/peer1
    fabric-ca-client enroll -u http://peer1:peer1pw@localhost:7054 -M $FABRIC_CA_CLIENT_HOME/msp

Enrolling an orderer is the same, except the path to the MSP directory is
the 'LocalMSPDir' setting in your orderer's orderer.yaml file.

Getting a CA certificate chain from another Fabric CA server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In general, the cacerts directory of the MSP directory must contain the certificate authority chains
of other certificate authorities, representing all of the roots of trust for the peer.

The ``fabric-ca-client getcacerts`` command is used to retrieve these certificate chains from other
Fabric CA server instances.

For example, the following will start a second Fabric CA server on localhost
listening on port 7055 with a name of "CA2".  This represents a completely separate
root of trust and would be managed by a different member on the blockchain.

.. code:: bash

    export FABRIC_CA_SERVER_HOME=$HOME/ca2
    fabric-ca-server start -b admin:ca2pw -p 7055 -n CA2

The following command will install CA2's certificate chain into peer1's MSP directory.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/peer1
    fabric-ca-client getcacert -u http://localhost:7055 -M $FABRIC_CA_CLIENT_HOME/msp

Reenrolling an Identity
~~~~~~~~~~~~~~~~~~~~~~~

Suppose your enrollment certificate is about to expire or has been compromised.
You can issue the reenroll command to renew your enrollment certificate as follows.

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/peer1
    fabric-ca-client reenroll

Revoking a certificate or identity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
An identity or a certificate can be revoked. Revoking an identity will revoke all
the certificates owned by the identity and will also prevent the identity from getting
any new certificates. Revoking a certificate will invalidate a single certificate.

In order to revoke a certificate or an identity, the calling identity must have
the ``hf.Revoker`` attribute. The revoking identity can only revoke a certificate
or an identity that has an affiliation that is equal to or prefixed by the revoking
identity's affiliation.

For example, a revoker with affiliation **orgs.org1** can revoke an identity
affiliated with **orgs.org1** or **orgs.org1.department1** but can't revoke an
identity affiliated with **orgs.org2**.

The following command disables an identity and revokes all of the certificates
associated with the identity. All future requests received by the Fabric CA server
from this identity will be rejected.

.. code:: bash

    fabric-ca-client revoke -e <enrollment_id> -r <reason>

The following are the supported reasons that can be specified using ``-r`` flag:

  1. unspecified
  2. keycompromise
  3. cacompromise
  4. affiliationchange
  5. superseded
  6. cessationofoperation
  7. certificatehold
  8. removefromcrl
  9. privilegewithdrawn
  10. aacompromise

For example, the bootstrap admin who is associated with root of the affiliation tree
can revoke **peer1**'s identity as follows:

.. code:: bash

    export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/clients/admin
    fabric-ca-client revoke -e peer1

An enrollment certificate that belongs to an identity can be revoked by
specifying its AKI (Authority Key Identifier) and serial number as follows:

.. code:: bash

    fabric-ca-client revoke -a xxx -s yyy -r <reason>

For example, you can get the AKI and the serial number of a certificate using the openssl command
and pass them to the ``revoke`` command to revoke the said certificate as follows:

.. code:: bash

   serial=$(openssl x509 -in userecert.pem -serial -noout | cut -d "=" -f 2)
   aki=$(openssl x509 -in userecert.pem -text | awk '/keyid/ {gsub(/ *keyid:|:/,"",$1);print tolower($0)}')
   fabric-ca-client revoke -s $serial -a $aki -r affiliationchange

Enabling TLS
~~~~~~~~~~~~

This section describes in more detail how to configure TLS for a Fabric CA client.

The following sections may be configured in the ``fabric-ca-client-config.yaml``.

.. code:: yaml

    tls:
      # Enable TLS (default: false)
      enabled: true
      certfiles:
        - root.pem
      client:
        certfile: tls_client-cert.pem
        keyfile: tls_client-key.pem

The **certfiles** option is the set of root certificates trusted by the
client. This will typically just be the root Fabric CA server's
certificate found in the server's home directory in the **ca-cert.pem**
file.

The **client** option is required only if mutual TLS is configured on
the server.

Contact specific CA instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a server is running multiple CA instances, requests can be directed to a
specific CA. By default, if no CA name is specified in the client request the
request will be directed to the default CA on the fabric-ca server. A CA name
can be specified on the command line of a client command as follows:

.. code:: bash

    fabric-ca-client enroll -u http://admin:adminpw@localhost:7054 --caname <caname>

`Back to Top`_

.. Licensed under Creative Commons Attribution 4.0 International License
   https://creativecommons.org/licenses/by/4.0/
