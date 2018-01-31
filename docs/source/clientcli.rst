Fabric-CA Client's CLI
======================

::

    Hyperledger Fabric Certificate Authority Client
    
    Usage:
      fabric-ca-client [command]
    
    Available Commands:
      affiliation Manage affiliations
      enroll      Enroll an identity
      gencrl      Generate a CRL
      gencsr      Generate a CSR
      getcacert   Get CA certificate chain
      identity    Manage identities
      reenroll    Reenroll an identity
      register    Register an identity
      revoke      Revoke an identity
      version     Prints Fabric CA Client version
    
    Flags:
          --caname string                  Name of CA
          --csr.cn string                  The common name field of the certificate signing request
          --csr.hosts stringSlice          A list of space-separated host names in a certificate signing request
          --csr.names stringSlice          A list of comma-separated CSR names of the form <name>=<value> (e.g. C=CA,O=Org1)
          --csr.serialnumber string        The serial number in a certificate signing request
      -d, --debug                          Enable debug level logging
          --enrollment.attrs stringSlice   A list of comma-separated attribute requests of the form <name>[:opt] (e.g. foo,bar:opt)
          --enrollment.label string        Label to use in HSM operations
          --enrollment.profile string      Name of the signing profile to use in issuing the certificate
      -H, --home string                    Client's home directory (default "$HOME/.fabric-ca-client")
          --id.affiliation string          The identity's affiliation
          --id.attrs stringSlice           A list of comma-separated attributes of the form <name>=<value> (e.g. foo=foo1,bar=bar1)
          --id.maxenrollments int          The maximum number of times the secret can be reused to enroll (default CA's Max Enrollment)
          --id.name string                 Unique name of the identity
          --id.secret string               The enrollment secret for the identity being registered
          --id.type string                 Type of identity being registered (e.g. 'peer, app, user') (default "client")
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
