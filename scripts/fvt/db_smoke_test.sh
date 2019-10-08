#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

SCRIPTDIR="$GOPATH/src/github.com/hyperledger/fabric-ca/scripts/fvt"
MYSQLSMOKECONFIG=$FABRIC_CA_DATA/smoke/caconfig.yml

mkdir -p "$(dirname ${MYSQLSMOKECONFIG})"
# Create base configuration using mysql
cat >$MYSQLSMOKECONFIG <<EOF
debug: true

db:
  type: mysql
  datasource: root:mysql@tcp(localhost:$MYSQL_PORT)/fabric_ca?tls=custom
  tls:
     enabled: true
     certfiles:
       - $TLS_ROOTCERT
     client:
       certfile: $TLS_CLIENTCERT
       keyfile: $TLS_CLIENTKEY
tls:
  enabled: true
  certfile: $TLS_SERVERCERT
  keyfile: $TLS_SERVERKEY

registry:
  # Maximum number of times a password/secret can be reused for enrollment
  # (default: -1, which means there is no limit)
  maxenrollments: -1

  # Contains identity information which is used when LDAP is disabled
  identities:
     - name: a
       pass: b
       type: client
       affiliation: ""
       maxenrollments: -1
       attrs:
          hf.Registrar.Roles: "client,user,peer,validator,auditor"
          hf.Registrar.DelegateRoles: "client,user,validator,auditor"
          hf.Revoker: true
          hf.IntermediateCA: true

affiliations:
   org1:
      - department1
      - department2
   org2:
      - department1
EOF

fabric-ca-server start -b a:b -c $MYSQLSMOKECONFIG -d &
if test $? -eq 1; then
  ErrorMsg "Failed to start server, with the latest configuration file version"
fi
$SCRIPTDIR/fabric-ca_setup.sh -K
