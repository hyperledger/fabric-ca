#!/bin/bash

#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

: ${TESTCASE:="idemix"}
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
CA_CFG_PATH="/tmp/idemixTesting"
. $SCRIPTDIR/fabric-ca_utils
RC=0

USERNAME="admin"
USERPSWD="adminpw"

function idemixCleanUp() {
    if [ "$1" = "postgres" ]; then
        psql -d postgres -c "DROP DATABASE fabric_ca"
    else
        mysql --host=localhost --user=root --password=mysql -e "drop database fabric_ca;"
    fi
    rm -rf $CA_CFG_PATH
}

function getCAInfo() {
    $FABRIC_CA_CLIENTEXEC getcainfo -H $CA_CFG_PATH/$USERNAME -u $PROTO${CA_HOST_ADDRESS}:$PROXY_PORT $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'getcainfo' command"

    PUBKEY="$CA_CFG_PATH/$USERNAME/msp/IssuerPublicKey"
    if [ ! -f $PUBKEY ]; then
        ErrorMsg "Issuer Public Key was not stored in the correct location"
    fi
}

function getIdemixCred() {
    $FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}${USERNAME}:$USERPSWD@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME --enrollment.type idemix -d $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command"

    CLIENTCERT="$CA_CFG_PATH/$USERNAME/msp/user/SignerConfig"
    if [ ! -f $CLIENTCERT ]; then
        ErrorMsg "Idemix credential was not stored in the correct location"
    fi
}

function runCommandsUsingIdemix() {
    $FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name testuser1 -d -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"

    $FABRIC_CA_CLIENTEXEC affiliation list -H $CA_CFG_PATH/$USERNAME -d -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'affiliation list' command"

    $FABRIC_CA_CLIENTEXEC identity list -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'identity list' command"

    $FABRIC_CA_CLIENTEXEC certificate list -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'certificate list' command"

    $FABRIC_CA_CLIENTEXEC gencrl -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'gencrl' command"

    $FABRIC_CA_CLIENTEXEC gencsr --csr.cn testGenCSR -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'gencsr' command"
}

function testIdemixWithRevokedID() {
    USERNAME2="admin2"
    USERPSWD2="adminpw2"

    $FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}${USERNAME2}:$USERPSWD2@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/$USERNAME2 --enrollment.type idemix $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command for 'admin2' - idemix"

    $FABRIC_CA_CLIENTEXEC revoke --revoke.name admin2 -H $CA_CFG_PATH/$USERNAME -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'revoke' command"

    $FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME2 --id.name testuser2 -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 1 || ErrorMsg "Should fail to complete 'register' command, the user with an Idemix credential has been revoked"
}

function testRHPool() {
    # Starting count at 3 because already enrolled 2 users above (admin and admin2)
    for i in $(seq 3 $((RHPOOLSIZE)))
        do
        $FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name user$i --id.secret user$i -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
        test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"
        $FABRIC_CA_CLIENTEXEC enroll -u "${PROTO}user$i:user$i@$CA_HOST_ADDRESS:$PROXY_PORT" -H $CA_CFG_PATH/user$i --enrollment.type idemix $TLSOPT
        test $? -eq 0 || ErrorMsg "Failed to complete 'enroll' command for 'user$i' - idemix"
    done

    # Epoch verification is currently disabled in 1.1, even thought a RH Pool Size was exhausted
    # and a new Epoch verification was generated this should fail since caller has an outdated CRI
    # in it's singerConfig. This will start to fail when Epoch verification is enabled again.
    $FABRIC_CA_CLIENTEXEC register -H $CA_CFG_PATH/$USERNAME --id.name newUser --id.secret user$i -d  -u "$PROTO${CA_HOST_ADDRESS}:$PROXY_PORT" $TLSOPT
    test $? -eq 0 || ErrorMsg "Failed to complete 'register' command"
}

function checkExpirationSQLExec() {
    sleep 2 # Give some time for the expiration timeout to occur
    grep "Cleaning up expired nonces for CA" /tmp/serverlog.txt # Check to make sure that cleaning up has actually started
    test $? -ne 0 && ErrorMsg "Cleaning up expired nonces never triggered"
    grep "Failed to remove expired nonces" /tmp/serverlog.txt # Check that bad sql error is not seen
    test $? -ne 1 && ErrorMsg "Failed to remove expired nonces, the SQL query failed to execute"
}

RHPOOLSIZE=10
export FABRIC_CA_SERVER_IDEMIX_RHPOOLSIZE=$RHPOOLSIZE
export FABRIC_CA_SERVER_IDEMIX_NONCEEXPIRATION=2s
export FABRIC_CA_SERVER_IDEMIX_NONCESWEEPINTERVAL=4s

for driver in postgres mysql; do
    ##### Start Fabric CA Server with #####
    $SCRIPTDIR/fabric-ca_setup.sh -I -S -X -D -d $driver 2>&1 | tee /tmp/serverlog.txt &
    pollFabricCa "" "" $CA_DEFAULT_PORT

    ###### Get Idemix Public Key ######
    getCAInfo

    ###### Get Idemix Credential ######
    getIdemixCred

    ###### Issue other client commands using Idemix Credential ######
    runCommandsUsingIdemix

    ###### Revoking an identity that has both x509 and Idemix credentials #######
    testIdemixWithRevokedID

    ###### Use up the RH Pool with idemix enrollments ######
    testRHPool

    ###### Test that no sql errors seen related to deleting expired nonces #######
    checkExpirationSQLExec

    $SCRIPTDIR/fabric-ca_setup.sh -K
    idemixCleanUp $driver
done

CleanUp $RC
exit $RC
