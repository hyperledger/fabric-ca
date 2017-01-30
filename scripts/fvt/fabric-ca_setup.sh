#!/bin/bash
FABRIC_CA="${GOPATH}/src/github.com/hyperledger/fabric-ca"
FABRIC_CAEXEC="$FABRIC_CA/bin/fabric-ca"
TESTDATA="$FABRIC_CA/testdata"
RUNCONFIG="$TESTDATA/runFabricCaFvt.json"
INITCONFIG="$TESTDATA/initFabricCaFvt.json"
DST_KEY="$TESTDATA/fabric-ca-key.pem"
DST_CERT="$TESTDATA/fabric-ca-cert.pem"
MYSQL_PORT="3306"
POSTGRES_PORT="5432"
export PGPASSWORD='postgres'
GO_VER="1.7.1"
ARCH="amd64"
RC=0

function ErrorExit() {
   echo "${1}...exiting"
   exit 1
}

function tolower() {
  echo "$1" | tr [:upper:] [:lower:]
}

function genRunconfig() {
   cat > $RUNCONFIG <<EOF
{
 "tls_disable":$TLS_DISABLE,
 "authentication": $AUTH,
 "driver":"$DRIVER",
 "data_source":"$DATASRC",
 "ca_cert":"$DST_CERT",
 "ca_key":"$DST_KEY",
 "tls":{
   "tls_cert":"$TESTDATA/tls_server-cert.pem",
   "tls_key":"$TESTDATA/tls_server-key.pem",
   "mutual_tls_ca":"$TESTDATA/root.pem",
   "db_client":{
     "ca_certfiles":["$TESTDATA/root.pem"],
     "client":{"keyfile":"$TESTDATA/tls_server-key.pem","certfile":"$TESTDATA/tls_server-cert.pem"}
   }
 },
 "user_registry": {
   "max_enrollments": $MAXENROLL
 },
 "users": {
    "admin": {
      "pass": "adminpw",
      "type": "client",
      "group": "bank_a",
      "attrs": [{"name":"hf.Registrar.Roles","value":"client,user,peer,validator,auditor"},
                {"name":"hf.Registrar.DelegateRoles", "value": "client,user,validator,auditor"},
                {"name":"hf.Revoker", "value": "true"}]
    },
    "admin2": {
      "pass": "adminpw2",
      "type": "client",
      "group": "bank_a",
      "attrs": [{"name":"hf.Registrar.Roles","value":"client,user,peer,validator,auditor"},
                {"name":"hf.Registrar.DelegateRoles", "value": "client,user,validator,auditor"},
                {"name":"hf.Revoker", "value": "true"}]
    },
    "revoker": {
      "pass": "revokerpw",
      "type": "client",
      "group": "bank_a",
      "attrs": [{"name":"hf.Revoker", "value": "true"}]
    },
    "notadmin": {
      "pass": "pass",
      "type": "client",
      "group": "bank_a",
      "attrs": [{"name":"hf.Registrar.Roles","value":"client,peer,validator,auditor"},
                {"name":"hf.Registrar.DelegateRoles", "value": "client"}]
    },
    "expiryUser": {
      "pass": "expirypw",
      "type": "client",
      "group": "bank_a"
    },
    "testUser": {
      "pass": "user1",
      "type": "client",
      "group": "bank_b",
      "attrs": []
    },
    "testUser2": {
      "pass": "user2",
      "type": "client",
      "group": "bank_c",
      "attrs": []
    },
    "testUser3": {
      "pass": "user3",
      "type": "client",
      "group": "bank_a",
      "attrs": []
    }
 },
 "groups": {
   "banks_and_institutions": {
     "banks": ["bank_a", "bank_b", "bank_c"],
     "institutions": ["institution_a"]
   }
 },
 "signing": {
    "default": {
       "usages": ["cert sign"],
       "expiry": "8000h",
       "crl_url": "http://localhost:$HTTP_PORT/TestCRL.crl",
       "ca_constraint": {"is_ca": true, "max_path_len":1},
       "ocsp_no_check": true,
       "not_before": "2016-12-30T00:00:00Z"
    },
    "expiry": {
       "usages": ["cert sign"],
       "expiry": "1s"
    }
 }
}
EOF

}

function genInitConfig() {
   cat > $INITCONFIG <<EOF
{
 "hosts": [
     "eca@hyperledger-server",
     "127.0.0.1",
     "hyperledger-server.example.com"
 ],
 "CN": "FVT FABRIC_CA Enrollment CA($KEYTYPE $KEYLEN)",
 "key": {
     "algo": "$KEYTYPE",
     "size": $KEYLEN
 },
 "names": [
     {
         "SN": "admin",
         "O": "Hyperledger",
         "O": "Fabric",
         "OU": "FABRIC_CA",
         "OU": "FVT",
         "STREET": "Miami Blvd.",
         "DC": "peer",
         "UID": "admin",
         "L": "Raleigh",
         "L": "RTP",
         "ST": "North Carolina",
         "C": "US"
     }
 ]
}
EOF
}

function usage() {
   echo "ARGS:"
   echo "  -d)   <DRIVER> - [sqlite3|mysql|postgres]"
   echo "  -n)   <FABRIC_CA_INSTANCES> - number of servers to start"
   echo "  -i)   <GITID> - ID for cloning git repo"
   echo "  -t)   <KEYTYPE> - rsa|ecdsa"
   echo "  -l)   <KEYLEN> - ecdsa: 256|384|521; rsa 2048|3072|4096"
   echo "  -c)   <SRC_CERT> - pre-existing server cert"
   echo "  -k)   <SRC_KEY> - pre-existing server key"
   echo "  -x)   <DATADIR> - local storage for client auth_info"
   echo "FLAGS:"
   echo "  -D)   set FABRIC_CA_DEBUG='true'"
   echo "  -R)   set RESET='true' - delete DB, server certs, client certs"
   echo "  -P)   set PREP='true'  - install mysql, postgres, pq"
   echo "  -C)   set CLONE='true' - clone fabric-ca repo"
   echo "  -B)   set BUILD='true' - build fabric-ca server"
   echo "  -I)   set INIT='true'  - run fabric-ca server init"
   echo "  -S)   set START='true' - start \$FABRIC_CA_INSTANCES number of servers"
   echo "  -X)   set PROXY='true' - start haproxy for \$FABRIC_CA_INSTANCES of fabric-ca servers"
   echo "  -K)   set KILL='true'  - kill all running fabric-ca instances and haproxy"
   echo "  -L)   list all running fabric-ca instances"
   echo " ?|h)  this help text"
   echo ""
   echo "Defaults: -d sqlite3 -n 1 -k ecdsa -l 256"
}

function runPSQL() {
   cmd="$1"
   opts="$2"
   wrk_dir="$(pwd)"
   cd /tmp
   /usr/bin/psql "$opts" -U postgres -h localhost -c "$cmd"
   cd $wrk_dir
}

function updateBase {
   apt-get update
   apt-get -y upgrade
   apt-get -y autoremove
   return $?
}

function installGolang {
   local rc=0
   curl -G -L https://storage.googleapis.com/golang/go${GO_VER}.linux-${ARCH}.tar.gz \
           -o /tmp/go${GO_VER}.linux-${ARCH}.tar.gz
   tar -C /usr/local -xzf /tmp/go${GO_VER}.linux-${ARCH}.tar.gz
   let rc+=$?
   apt-get install -y golang-golang-x-tools
   let rc+=$?
   return $rc
}

function installDocker {
   local rc=0
   local codename=$(lsb_release -c | awk '{print $2}')
   local kernel=$(uname -r)
   apt-get install apt-transport-https ca-certificates \
                linux-image-extra-$kernel linux-image-extra-virtual
   echo "deb https://apt.dockerproject.org/repo ubuntu-${codename} main" >/tmp/docker.list
   cp /tmp/docker.list /etc/apt/sources.list.d/docker.list
   apt-key adv --keyserver hkp://ha.pool.sks-keyservers.net:80 \
                    --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
   apt-get update
   apt-get -y upgrade
   apt-get -y install docker-engine || let rc+=1
   curl -L https://github.com/$(curl -s -L https://github.com/docker/compose/releases | awk -v arch=$(uname -s)-$(uname -p) -F'"' '$0~arch {print $2;exit}') -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
   groupadd docker
   usermod -aG docker $(who are you | awk '{print $1}')
   return $rc
}

function updateSudoers() {
   local tmpfile=/tmp/sudoers
   local rc=0
   sudo cp /etc/sudoers $tmpfile
   echo 'ibmadmin ALL=(ALL) NOPASSWD:ALL' | tee -a $tmpfile
   sudo uniq $tmpfile | sudo tee $tmpfile
   sudo visudo -c -f $tmpfile
   test "$?" -eq "0" && sudo cp $tmpfile /etc/sudoers || rc=1
   sudo rm -f $tmpfile
   return $rc
}

function installPrereq() {
   updateBase || ErrorExit "updateBase failed"
   #updateSudoers || ErrorExit "updateSudoers failed"
   installGolang || ErrorExit "installGolang failed"
   installDocker || ErrorExit "installDocker failed"
   go get github.com/go-sql-driver/mysql || ErrorExit "install go-sql-driver failed"
   go get github.com/lib/pq || ErrorExit "install pq failed"
   apt-get -y install haproxy postgresql postgresql-contrib \
                   vim-haproxy haproxy-doc postgresql-doc locales-all \
                   libdbd-pg-perl isag jq git || ErrorExit "haproxy installed failed"
   export DEBIAN_FRONTEND=noninteractive
   apt-get -y purge mysql-server
   apt-get -y purge mysql-server-core
   apt-get -y purge mysql-common
   apt-get -y install debconf-utils zsh htop
   rm -rf /var/log/mysql
   rm -rf /var/log/mysql.*
   rm -rf /var/lib/mysql
   rm -rf /etc/mysql
   echo "mysql-server mysql-server/root_password password mysql" | debconf-set-selections
   echo "mysql-server mysql-server/root_password_again password mysql" | debconf-set-selections
   apt-get install -y mysql-client mysql-common \
                           mysql-server --fix-missing --fix-broken || ErrorExit "install mysql failed"
   apt -y autoremove
   runPSQL "ALTER USER postgres WITH PASSWORD 'postgres';"
}

function cloneFabricCa() {
   test -d ${GOPATH}/src/github.com/hyperledger || mkdir -p ${GOPATH}/src/github.com/hyperledger
   cd ${GOPATH}/src/github.com/hyperledger
   git clone http://gerrit.hyperledger.org/r/fabric-ca || ErrorExit "git clone of fabric-ca failed"
}

function buildFabricCa(){
   cd $FABRIC_CA
   make fabric-ca || ErrorExit "buildFabricCa failed"
}

function resetFabricCa(){
   killAllFabricCas
   rm -rf $DATADIR
   rm $TESTDATA/fabric_ca.db
   cd /tmp
   /usr/bin/dropdb 'fabric_ca' -U postgres -h localhost -w
   mysql --host=localhost --user=root --password=mysql -e 'DROP DATABASE IF EXISTS fabric_ca;'
}

function listFabricCa(){
   echo "Listening servers;"
   lsof -n -i tcp:9888


   case $DRIVER in
      mysql)
         echo ""
         mysql --host=localhost --user=root --password=mysql -e 'show tables' fabric_ca
         echo "Users:"
         mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM "users";' fabric_ca
      ;;
      postgres)
         echo ""
         runPSQL '\l fabric_ca' | sed 's/^/   /;1s/^ *//;1s/$/:/'

         echo "Users:"
         runPSQL 'SELECT * FROM "users";' '--dbname=fabric_ca' | sed 's/^/   /'
      ;;
      sqlite3) sqlite3 "$dbfile" 'SELECT * FROM "users" ;;' | sed 's/^/   /'
   esac
}

function initFabricCa() {
   test -f $FABRIC_CAEXEC || ErrorExit "fabric-ca executable not found (use -B to build)"
   cd $FABRIC_CA/bin

   export FABRIC_CA_HOME=$HOME/fabric-ca
   genInitConfig
   $FABRIC_CAEXEC server init $INITCONFIG

   rm $DST_KEY $DST_CERT
   cp $SRC_KEY $DST_KEY
   cp $SRC_CERT $DST_CERT
   echo "FABRIC_CA server initialized"
   if $($FABRIC_CA_DEBUG); then
      openssl x509 -in $DST_CERT -noout -issuer -subject -serial \
                   -dates -nameopt RFC2253| sed 's/^/   /'
      openssl x509 -in $DST_CERT -noout -text |
         awk '
            /Subject Alternative Name:/ {
               gsub(/^ */,"")
               printf $0"= "
               getline; gsub(/^ */,"")
               print
            }'| sed 's/^/   /'
      openssl x509 -in $DST_CERT -noout -pubkey |
         openssl $KEYTYPE -pubin -noout -text 2>/dev/null| sed 's/Private/Public/'
      openssl $KEYTYPE -in $DST_KEY -text 2>/dev/null
   fi
}


function startHaproxy() {
   local inst=$1
   local i=0
   local proxypids=$(lsof -n -i tcp | awk '$1=="haproxy" && !($2 in a) {a[$2]=$2;print a[$2]}')
   test -n "$proxypids" && kill $proxypids
   #sudo sed -i 's/ *# *$UDPServerRun \+514/$UDPServerRun 514/' /etc/rsyslog.conf
   #sudo sed -i 's/ *# *$ModLoad \+imudp/$ModLoad imudp/' /etc/rsyslog.conf
   case $TLS_DISABLE in
     false)
   haproxy -f  <(echo "global
      log /dev/log	local0 debug
      log /dev/log	local1 debug
      daemon
defaults
      log     global
      option  dontlognull
      maxconn 1024
      timeout connect 5000
      timeout client 50000
      timeout server 50000

frontend haproxy
      bind *:8888
      mode tcp
      option tcplog
      default_backend fabric-cas

backend fabric-cas
      mode tcp
      balance roundrobin";
   while test $((i++)) -lt $inst; do
      echo "      server server$i  127.0.0.$i:9888"
   done)
   ;;
   true)
   haproxy -f  <(echo "global
      log /dev/log	local0 debug
      log /dev/log	local1 debug
      daemon
defaults
      log     global
      mode http
      option  httplog
      option  dontlognull
      maxconn 1024
      timeout connect 5000
      timeout client 50000
      timeout server 50000
      option forwardfor

listen stats
      bind *:10888
      stats enable
      stats uri /
      stats enable

frontend haproxy
      bind *:8888
      mode http
      option tcplog
      default_backend fabric-cas

backend fabric-cas
      mode http
      http-request set-header X-Forwarded-Port %[dst_port]
      balance roundrobin";
   while test $((i++)) -lt $inst; do
      echo "      server server$i  127.0.0.$i:9888"
   done)
   ;;
   esac

}

function startFabricCa() {
   local inst=$1
   local start=$SECONDS
   local timeout=8
   local now=0
   local server_addr=127.0.0.$inst
   local server_port=9888

   cd $FABRIC_CA/bin
   inst=0
   $FABRIC_CAEXEC server start -address $server_addr -port $server_port -ca $DST_CERT \
                    -ca-key $DST_KEY -config $RUNCONFIG 2>&1 | sed 's/^/     /' &
   until test "$started" = "$server_addr:$server_port" -o "$now" -gt "$timeout"; do
      started=$(ss -ltnp src $server_addr:$server_port | awk 'NR!=1 {print $4}')
      sleep .5
      let now+=1
   done
   printf "FABRIC_CA server on $server_addr:$server_port "
   if test "$started" = "$server_addr:$server_port"; then
      echo "STARTED"
   else
      RC=$((RC+1))
      echo "FAILED"
   fi
}


function killAllFabricCas() {
   local fabric_capids=$(ps ax | awk '$5~/fabric-ca/ {print $1}')
   local proxypids=$(lsof -n -i tcp | awk '$1=="haproxy" && !($2 in a) {a[$2]=$2;print a[$2]}')
   test -n "$fabric_capids" && kill $fabric_capids
   test -n "$proxypids" && kill $proxypids
}

while getopts "\?hPRCBISKXLDTAd:t:l:n:i:c:k:x:g:m:p:" option; do
  case "$option" in
     d)   DRIVER="$OPTARG" ;;
     p)   HTTP_PORT="$OPTARG" ;;
     n)   FABRIC_CA_INSTANCES="$OPTARG" ;;
     i)   GITID="$OPTARG" ;;
     t)   KEYTYPE=$(tolower $OPTARG);;
     l)   KEYLEN="$OPTARG" ;;
     c)   SRC_CERT="$OPTARG";;
     k)   SRC_KEY="$OPTARG" ;;
     x)   DATADIR="$OPTARG" ;;
     m)   MAXENROLL="$OPTARG" ;;
     g)   SERVERCONFIG="$OPTARG" ;;
     D)   export FABRIC_CA_DEBUG='true' ;;
     A)   AUTH="false" ;;
     P)   PREP="true"  ;;
     R)   RESET="true"  ;;
     C)   CLONE="true" ;;
     B)   BUILD="true" ;;
     I)   INIT="true" ;;
     S)   START="true" ;;
     X)   PROXY="true" ;;
     K)   KILL="true" ;;
     L)   LIST="true" ;;
     T)   TLS_ON="true" ;;
   \?|h)  usage
          exit 1
          ;;
  esac
done

# regarding tls:
#    honor the command-line setting to turn on TLS
#      else honor the envvar
#        else (default) turn off tls
if test -n "$TLS_ON"; then
   TLS_DISABLE='false'
else
   case "$FABRIC_TLS" in
      true) TLS_DISABLE='false' ;;
     false) TLS_DISABLE='true'  ;;
         *) TLS_DISABLE='true'  ;;
   esac
fi

test -z "$DATADIR" && DATADIR="$HOME/fabric-ca"
test -z "$SRC_KEY" && SRC_KEY="$DATADIR/server-key.pem"
test -z "$SRC_CERT" && SRC_CERT="$DATADIR/server-cert.pem"
: ${HTTP_PORT="3755"}
: ${MAXENROLL="1"}
: ${AUTH="true"}
: ${DRIVER="sqlite3"}
: ${FABRIC_CA_INSTANCES=1}
: ${FABRIC_CA_DEBUG="false"}
: ${GITID="rennman"}
: ${LIST="false"}
: ${PREP="false"}
: ${RESET="false"}
: ${CLONE="false"}
: ${BUILD="false"}
: ${INIT="false"}
: ${START="false"}
: ${PROXY="false"}
: ${HTTP="true"}
: ${KILL="false"}
: ${KEYTYPE="ecdsa"}
: ${KEYLEN="256"}
test $KEYTYPE = "rsa" && SSLKEYCMD=$KEYTYPE || SSLKEYCMD="ec"

case $DRIVER in
   postgres) DATASRC="dbname=fabric_ca host=127.0.0.1 port=$POSTGRES_PORT user=postgres password=postgres sslmode=disable" ;;
   sqlite3)   DATASRC="fabric_ca.db"; dbfile="$TESTDATA/fabric_ca.db" ;;
   mysql)    DATASRC="root:mysql@tcp(localhost:$MYSQL_PORT)/fabric_ca?parseTime=true" ;;
esac

$($LIST)  && listFabricCa
$($PREP)  && installPrereq
$($RESET) && resetFabricCa
$($CLONE) && cloneFabricCa
$($BUILD) && buildFabricCa
$($INIT) && initFabricCa
$($KILL)  && killAllFabricCas
$($PROXY) && startHaproxy $FABRIC_CA_INSTANCES

if $($START); then
   test -z "$SERVERCONFIG" && genRunconfig || cp "$SERVERCONFIG" "$RUNCONFIG"
   inst=0
   while test $((inst++)) -lt $FABRIC_CA_INSTANCES; do
      startFabricCa $inst
   done
fi
exit $RC
