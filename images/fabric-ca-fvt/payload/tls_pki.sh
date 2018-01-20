#!/bin/bash
FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="/etc/hyperledger/fabric-ca"
export HOME=$SCRIPTDIR
PKI="$SCRIPTDIR/pki"
. $SCRIPTDIR/fabric-ca_utils
CaDir='/tmp/CAs'
RC=0

curr_year=$(date +"%g")
ten=$((curr_year+10))
five=$((curr_year+5))
two=$((curr_year+2))

now=$(date +"%g%m%d%H%M%SZ")
ten_year=$(date +"$ten%m%d%H%M%SZ")
five_year=$(date +"$five%m%d%H%M%SZ")
two_year=$(date +"$two%m%d%H%M%SZ")

KeyType="$1"
case ${KeyType:=rsa} in
    ec) CaKeyLength=521
        CaDigest="sha512"
        EeKeyLength=384
        EeDigest="sha384"
   ;;
   rsa) CaKeyLength=4096
        CaDigest="sha512"
        EeKeyLength=2048
        EeDigest="sha256"
   ;;
   dsa) CaKeyLength=512
        CaDigest="sha256"
        EeKeyLength=512
        EeDigest="sha256"
   ;;
     *) ErrorExit "Unsupported keytype $KeyType"
   ;;
esac

# Shared variables
IpV4Addr='127.0.0.1'
IpV6Addr='::1'
HostName='localhost'
CaKeyUsage='keyCertSign,cRLSign,digitalSignature'
EeKeyUsage='digitalSignature,nonRepudiation'
CaExpiry="$ten_year"
RaExpiry="$five_year"
EeExpiry="$two_year"

# RootCa variables
RootCa='FabricTlsRootCa'
RootSubject="/C=US/ST=North Carolina/L=RTP/O=Hyperledger/OU=fabric-ca/CN=$RootCa/"
RootEmail="$RootCa@localhost"

# SubCa variables
SubCa='FabricTlsSubCa'
SubSubject="/C=US/ST=North Carolina/L=RTP/O=Hyperledger/OU=fabric-ca/CN=$SubCa/"
SubEmail="$SubCa@localhost"

# TlsRa variables
TlsRa='FabricTlsRa'
TlsRaSubject="/C=US/ST=North Carolina/L=RTP/O=Hyperledger/OU=fabric-ca/CN=$TlsRa/"
TlsRaEmail="$TlsRa@localhost"

# TlsServerEE variables
TlsServerEE='FabricTlsServerEE'
TlsServerSubject="/C=US/ST=North Carolina/L=RTP/O=Hyperledger/OU=fabric-ca/CN=$TlsServerEE/"
TlsServerEmail="$TlsServerEE@localhost"

# TlsClientEE variables
TlsClientEE='FabricTlsClientEE'
TlsClientSubject="/C=US/ST=North Carolina/L=RTP/O=Hyperledger/OU=fabric-ca/CN=$TlsClientEE/"
TlsClientEmail="$TlsClientEE@localhost"

cd $HOME

rm -rf $CaDir/$RootCa
rm -rf $CaDir/$SubCa
rm -rf $CaDir/$TlsRa

# TLS root cert
$PKI -f newca -a $RootCa -n "$RootSubject" -t $KeyType -l $CaKeyLength \
     -d $CaDigest -e $CaExpiry -K "$CaKeyUsage" -p $RootCa -x <<EOF
$IpV4Addr
"$IpV6Addr"
$HostName
"$RootEmail"
Y
EOF

# TLS SubCa
$PKI -f newsub -a $RootCa -b $SubCa -n "$SubSubject" -t $KeyType -l $CaKeyLength \
     -d $CaDigest -e $CaExpiry -K "$CaKeyUsage" -p $SubCa -x <<EOF
$IpV4Addr
"$IpV6Addr"
$HostName
$SubEmail
Y
EOF

# TLS Ra
$PKI -f newsub -a $SubCa -b $TlsRa -n "$TlsRaSubject" -t $KeyType -l $CaKeyLength \
     -d $CaDigest -e $RaExpiry -K "$CaKeyUsage" -p $TlsRaCa -x <<EOF
$IpV4Addr
"$IpV6Addr"
$HostName
$TlsRaEmail
Y
EOF

# TLS Server
$PKI -f newcert -a $TlsRa -n "$TlsServerSubject" -t $KeyType -l $EeKeyLength \
     -d $EeDigest -e $EeExpiry -K "$EeKeyUsage" -E serverAuth -p $TlsServerEE -x <<EOF
$IpV4Addr
"$IpV6Addr"
$HostName
$TlsServerEmail
Y
y
y
EOF

# TLS Client
$PKI -f newcert -a $TlsRa -n "$TlsClientSubject" -t $KeyType -l $EeKeyLength \
     -d $EeDigest -e $EeExpiry -K "$EeKeyUsage" -E clientAuth -p $TlsClientEE -x <<EOF
$IpV4Addr
"$IpV6Addr"
$HostName
$TlsClientEmail
Y
y
y
EOF

cat ${TlsRa}*cert.pem ${SubCa}*cert.pem ${RootCa}*cert.pem > FabricTlsPkiBundle.pem
