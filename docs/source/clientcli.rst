=======================
Fabric-CA Client's CLI
=======================

::

    Hyperledger Fabric Certificate Authority Client
    
    Usage:
      fabric-ca-client [command]
    
    Available Commands:
      affiliation Manage affiliations
      certificate Manage certificates
      enroll      Enroll an identity
      gencrl      Generate a CRL
      gencsr      Generate a CSR
      getcainfo   Get CA certificate chain and Idemix public key
      identity    Manage identities
      reenroll    Reenroll an identity
      register    Register an identity
      revoke      Revoke an identity
      version     Prints Fabric CA Client version
    
    Flags:
          --caname string                  Name of CA
          --csr.cn string                  The common name field of the certificate signing request
          --csr.hosts stringSlice          A list of comma-separated host names in a certificate signing request
          --csr.keyrequest.algo string     Specify key algorithm
          --csr.keyrequest.size int        Specify key size
          --csr.names stringSlice          A list of comma-separated CSR names of the form <name>=<value> (e.g. C=CA,O=Org1)
          --csr.serialnumber string        The serial number in a certificate signing request
          --enrollment.attrs stringSlice   A list of comma-separated attribute requests of the form <name>[:opt] (e.g. foo,bar:opt)
          --enrollment.label string        Label to use in HSM operations
          --enrollment.profile string      Name of the signing profile to use in issuing the certificate
          --enrollment.type string         The type of enrollment request: 'x509' or 'idemix' (default "x509")
      -H, --home string                    Client's home directory (default "$HOME/.fabric-ca-client")
          --id.affiliation string          The identity's affiliation
          --id.attrs stringSlice           A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)
          --id.maxenrollments int          The maximum number of times the secret can be reused to enroll (default CA's Max Enrollment)
          --id.name string                 Unique name of the identity
          --id.secret string               The enrollment secret for the identity being registered
          --id.type string                 Type of identity being registered (e.g. 'peer, app, user') (default "client")
          --loglevel string                Set logging level (info, warning, debug, error, fatal, critical)
      -M, --mspdir string                  Membership Service Provider directory (default "msp")
      -m, --myhost string                  Hostname to include in the certificate signing request during enrollment (default "$HOSTNAME")
      -a, --revoke.aki string              AKI (Authority Key Identifier) of the certificate to be revoked
      -e, --revoke.name string             Identity whose certificates should be revoked
      -r, --revoke.reason string           Reason for revocation
      -s, --revoke.serial string           Serial number of the certificate to be revoked
          --tls.certfiles stringSlice      A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)
          --tls.client.certfile string     PEM-encoded certificate file when mutual authenticate is enabled
          --tls.client.keyfile string      PEM-encoded key file when mutual authentication is enabled
      -u, --url string                     URL of fabric-ca-server (default "http://localhost:7054")
    
    Use "fabric-ca-client [command] --help" for more information about a command.

Identity Command
==================

::

    Manage identities
    
    Usage:
      fabric-ca-client identity [command]
    
    Available Commands:
      add         Add identity
      list        List identities
      modify      Modify identity
      remove      Remove identity
    
    -----------------------------
    
    Add an identity
    
    Usage:
      fabric-ca-client identity add <id> [flags]
    
    Examples:
    fabric-ca-client identity add user1 --type peer
    
    Flags:
          --affiliation string   The identity's affiliation
          --attrs stringSlice    A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)
          --json string          JSON string for adding a new identity
          --maxenrollments int   The maximum number of times the secret can be reused to enroll (default CA's Max Enrollment)
          --secret string        The enrollment secret for the identity being added
          --type string          Type of identity being registered (e.g. 'peer, app, user') (default "user")
    
    -----------------------------
    
    List identities visible to caller
    
    Usage:
      fabric-ca-client identity list [flags]
    
    Flags:
          --id string   Get identity information from the fabric-ca server
    
    -----------------------------
    
    Modify an existing identity
    
    Usage:
      fabric-ca-client identity modify <id> [flags]
    
    Examples:
    fabric-ca-client identity modify user1 --type peer
    
    Flags:
          --affiliation string   The identity's affiliation
          --attrs stringSlice    A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)
          --json string          JSON string for modifying an existing identity
          --maxenrollments int   The maximum number of times the secret can be reused to enroll
          --secret string        The enrollment secret for the identity
          --type string          Type of identity being registered (e.g. 'peer, app, user')
    
    -----------------------------
    
    Remove an identity
    
    Usage:
      fabric-ca-client identity remove <id> [flags]
    
    Examples:
    fabric-ca-client identity remove user1
    
    Flags:
          --force   Forces removing your own identity
    

Affiliation Command
=====================

::

    Manage affiliations
    
    Usage:
      fabric-ca-client affiliation [command]
    
    Available Commands:
      add         Add affiliation
      list        List affiliations
      modify      Modify affiliation
      remove      Remove affiliation
    
    -----------------------------
    
    Add affiliation
    
    Usage:
      fabric-ca-client affiliation add <affiliation> [flags]
    
    Flags:
          --force   Creates parent affiliations if they do not exist
    
    -----------------------------
    
    List affiliations visible to caller
    
    Usage:
      fabric-ca-client affiliation list [flags]
    
    Flags:
          --affiliation string   Get affiliation information from the fabric-ca server
    
    -----------------------------
    
    Modify existing affiliation
    
    Usage:
      fabric-ca-client affiliation modify <affiliation> [flags]
    
    Flags:
          --force         Forces identities using old affiliation to use new affiliation
          --name string   Rename the affiliation
    
    -----------------------------
    
    Remove affiliation
    
    Usage:
      fabric-ca-client affiliation remove <affiliation> [flags]
    
    Flags:
          --force   Forces removal of any child affiliations and any identities associated with removed affiliations
    

Certificate Command
=====================

::

    Manage certificates
    
    Usage:
      fabric-ca-client certificate [command]
    
    Available Commands:
      list        List certificates
    
    -----------------------------
    
    List all certificates which are visible to the caller and match the flags
    
    Usage:
      fabric-ca-client certificate list [flags]
    
    Examples:
    fabric-ca-client certificate list --id admin --expiration 2018-01-01::2018-01-30
    fabric-ca-client certificate list --id admin --expiration 2018-01-01T01:30:00z::2018-01-30T11:30:00z
    fabric-ca-client certificate list --id admin --expiration -30d::-15d
    
    Flags:
          --aki string          Get certificates for this AKI
          --expiration string   Get certificates which expire between the UTC timestamp (RFC3339 format) or duration specified (e.g. <begin_time>::<end_time>)
          --id string           Get certificates for this enrollment ID
          --notexpired          Don't return expired certificates
          --notrevoked          Don't return revoked certificates
          --revocation string   Get certificates that were revoked between the UTC timestamp (RFC3339 format) or duration specified (e.g. <begin_time>::<end_time>)
          --serial string       Get certificates for this serial number
          --store string        Store requested certificates in this location
    
