#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FABRIC_CA="$GOPATH/src/github.com/hyperledger/fabric-ca"
SCRIPTDIR="$FABRIC_CA/scripts/fvt"
. $SCRIPTDIR/fabric-ca_utils
GO_VER="1.7.1"
ARCH="amd64"
RC=0

function usage() {
  echo "ARGS:"
  echo "  -d)   <DRIVER> - [sqlite3|mysql|postgres]"
  echo "  -n)   <FABRIC_CA_INSTANCES> - number of servers to start"
  echo "  -t)   <KEYTYPE> - rsa|ecdsa"
  echo "  -l)   <KEYLEN> - ecdsa: 256|384|521; rsa 2048|3072|4096"
  echo "  -c)   <SRC_CERT> - pre-existing server cert"
  echo "  -k)   <SRC_KEY> - pre-existing server key"
  echo "  -x)   <DATADIR> - local storage for client auth_info"
  echo "FLAGS:"
  echo "  -D)   set FABRIC_CA_DEBUG='true'"
  echo "  -R)   set RESET='true' - delete DB, server certs, client certs"
  echo "  -I)   set INIT='true'  - run fabric-ca server init"
  echo "  -S)   set START='true' - start \$FABRIC_CA_INSTANCES number of servers"
  echo "  -X)   set PROXY='true' - start haproxy for \$FABRIC_CA_INSTANCES of fabric-ca servers"
  echo "  -K)   set KILL='true'  - kill all running fabric-ca instances and haproxy"
  echo "  -L)   list all running fabric-ca instances"
  echo "  -P)   Enable profiling port on the server"
  echo " ?|h)  this help text"
  echo ""
  echo "Defaults: -d sqlite3 -n 1 -k ecdsa -l 256"
}

runPSQL() {
  local cmd="$1"
  local opts="$2"
  local wrk_dir="$(pwd)"
  cd /tmp
  /usr/bin/psql "$opts" -U postgres -h localhost -c "$cmd"
  local rc=$?
  cd $wrk_dir
  return $rc
}

resetFabricCa() {
  killAllFabricCas
  rm -rf $DATADIR >/dev/null
  test -f $(pwd)/${DBNAME}* && rm $(pwd)/${DBNAME}*
  cd /tmp

  # Base server and cluster servers
  for i in "" $(seq ${CACOUNT:-0}); do
    test -z $i && dbSuffix="" || dbSuffix="_ca$i"
    mysql --host=localhost --user=root --password=mysql -e 'show tables' ${DBNAME}${dbSuffix} >/dev/null 2>&1
    mysql --host=localhost --user=root --password=mysql -e "DROP DATABASE IF EXISTS ${DBNAME}${dbSuffix}" >/dev/null 2>&1
    /usr/bin/dropdb "${DBNAME}${dbSuffix}" -U postgres -h localhost -w --if-exists 2>/dev/null
  done
}

listFabricCa() {
  echo "Listening servers;"
  local port=${USER_CA_PORT-$CA_DEFAULT_PORT}
  local inst=0
  while test $((inst)) -lt $FABRIC_CA_INSTANCES; do
    lsof -n -i tcp:$((port + $inst))
    inst=$((inst + 1))
  done

  # Base server and cluster servers
  for i in "" $(seq ${CACOUNT:-0}); do
    test -z $i && dbSuffix="" || dbSuffix="_ca$i"
    echo ""
    echo " ======================================"
    echo " ========> Dumping ${DBNAME}${dbSuffix} Database"
    echo " ======================================"
    case $DRIVER in
    mysql)
      echo ""
      echo "Users:"
      mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM users;' ${DBNAME}${dbSuffix}
      if $($FABRIC_CA_DEBUG); then
        echo "Certificates:"
        mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM certificates;' ${DBNAME}${dbSuffix}
        echo "Affiliations:"
        mysql --host=localhost --user=root --password=mysql -e 'SELECT * FROM affiliations;' ${DBNAME}${dbSuffix}
      fi
      ;;
    postgres)
      echo ""
      runPSQL "\l ${DBNAME}${dbSuffix}" | sed 's/^/   /;1s/^ *//;1s/$/:/'

      echo "Users:"
      runPSQL "SELECT * FROM USERS;" "--dbname=${DBNAME}${dbSuffix}" | sed 's/^/   /'
      if $($FABRIC_CA_DEBUG); then
        echo "Certificates::"
        runPSQL "SELECT * FROM CERTIFICATES;" "--dbname=${DBNAME}${dbSuffix}" | sed 's/^/   /'
        echo "Affiliations:"
        runPSQL "SELECT * FROM AFFILIATIONS;" "--dbname=${DBNAME}${dbSuffix}" | sed 's/^/   /'
      fi
      ;;
    sqlite3)
      test -z $i && DBDIR=$DATADIR || DBDIR="$DATADIR/ca/ca$i"
      sqlite3 "$DBDIR/$DBNAME" 'SELECT * FROM USERS ;;' | sed 's/^/   /'
      if $($FABRIC_CA_DEBUG); then
        sqlite3 "$DATASRC" 'SELECT * FROM CERTIFICATES;' | sed 's/^/   /'
        sqlite3 "$DATASRC" 'SELECT * FROM AFFILIATIONS;' | sed 's/^/   /'
      fi
      ;;
    esac
  done
}

function initFabricCa() {
  test -f $FABRIC_CA_SERVEREXEC || ErrorExit "fabric-ca executable not found in src tree"
  $FABRIC_CA_SERVEREXEC init -c $RUNCONFIG $PARENTURL $args
  rc1=$?
  if test $rc1 -eq 1; then
    return $rc1
  fi
  echo "FABRIC_CA server initialized"
}

function startHaproxy() {
  local inst=$1
  local i=0
  local proxypids=$(lsof -n -i tcp | awk '$1=="haproxy" && !($2 in a) {a[$2]=$2;print a[$2]}')
  test -n "$proxypids" && kill $proxypids
  local server_port=${USER_CA_PORT-$CA_DEFAULT_PORT}
  haproxy -f <(
    echo "global
      log 127.0.0.1 local2
      daemon
defaults
      log     global
      option  dontlognull
      maxconn 4096
      timeout connect 30000
      timeout client 300000
      timeout server 300000

frontend haproxy
      bind *:$PROXY_PORT
      mode tcp
      option tcplog
      default_backend fabric-cas

backend fabric-cas
   mode tcp
   balance roundrobin"

    # For each requested instance passed to startHaproxy
    # (which is determined by the -n option passed to the
    # main script) create a backend server in haproxy config
    # Each server binds to a unique port on INADDR_ANY
    while test $((i)) -lt $inst; do
      echo "      server server$i  localhost:$((server_port + $i))"
      i=$((i + 1))
    done
    i=0

    if test -n "$FABRIC_CA_SERVER_PROFILE_PORT"; then
      echo "
frontend haproxy-profile
      bind *:8889
      mode http
      option tcplog
      default_backend fabric-ca-profile

backend fabric-ca-profile
      mode http
      http-request set-header X-Forwarded-Port %[dst_port]
      balance roundrobin"
      while test $((i)) -lt $inst; do
        echo "      server server$i  localhost:$((FABRIC_CA_SERVER_PROFILE_PORT + $i))"
        i=$((i + 1))
      done
      i=0
    fi

    if test -n "$FABRIC_CA_INTERMEDIATE_SERVER_PORT"; then
      echo "
frontend haproxy-intcas
      bind *:$INTERMEDIATE_PROXY_PORT
      mode tcp
      option tcplog
      default_backend fabric-intcas

backend fabric-intcas
   mode tcp
   balance roundrobin"

      while test $((i)) -lt $inst; do
        echo "      server intserver$i  localhost:$((INTERMEDIATE_CA_DEFAULT_PORT + $i))"
        i=$((i + 1))
      done
      i=0
    fi
  )

}

function startFabricCa() {
  local inst=$1
  local start=$SECONDS
  local timeout="$TIMEOUT"
  local now=0
  local server_addr=0.0.0.0
  local polladdr=$server_addr
  local port=${USER_CA_PORT-$CA_DEFAULT_PORT}
  port=$((port + $inst))
  # if not explcitly set, use default
  test -n "${port}" && local server_port="--port $port" || local server_port=""
  test -n "${CACOUNT}" && local cacount="--cacount ${CACOUNT}"

  if test -n "$FABRIC_CA_SERVER_PROFILE_PORT"; then
    local profile_port=$((FABRIC_CA_SERVER_PROFILE_PORT + $inst))
    FABRIC_CA_SERVER_PROFILE_PORT=$profile_port $FABRIC_CA_SERVEREXEC start --address $server_addr $server_port --ca.certfile $DST_CERT \
      --ca.keyfile $DST_KEY --config $RUNCONFIG $PARENTURL 2>&1 &
  else
    #      $FABRIC_CA_SERVEREXEC start --address $server_addr $server_port --ca.certfile $DST_CERT \
    #                     --ca.keyfile $DST_KEY $cacount --config $RUNCONFIG $args > $DATADIR/server${port}.log 2>&1 &
    $FABRIC_CA_SERVEREXEC start --address $server_addr $server_port --ca.certfile $DST_CERT \
      --ca.keyfile $DST_KEY $cacount --config $RUNCONFIG $args 2>&1 &
  fi

  printf "FABRIC_CA server on $server_addr:$port "
  test "$server_addr" = "0.0.0.0" && polladdr="127.0.0.1"
  pollFabricCa "" "$server_addr" "$port" "" "$TIMEOUT"
  if test "$?" -eq 0; then
    echo " STARTED"
  else
    RC=$((RC + 1))
    echo " FAILED"
  fi
}

function killAllFabricCas() {
  local fabric_capids=$(ps ax | awk '$5~/fabric-ca/ {print $1}')
  local proxypids=$(lsof -n -i tcp | awk '$1=="haproxy" && !($2 in a) {a[$2]=$2;print a[$2]}')
  test -n "$fabric_capids" && kill $fabric_capids
  test -n "$proxypids" && kill $proxypids
}

while getopts "\?hRCISKXLDTAPNad:t:l:n:c:k:x:g:m:p:r:o:u:U:" option; do
  case "$option" in
  a) LDAP_ENABLE="true" ;;
  o) TIMEOUT="$OPTARG" ;;
  u) CACOUNT="$OPTARG" ;;
  d) DRIVER="$OPTARG" ;;
  r) USER_CA_PORT="$OPTARG" ;;
  p) HTTP_PORT="$OPTARG" ;;
  n) FABRIC_CA_INSTANCES="$OPTARG" ;;
  t) KEYTYPE=$(tolower $OPTARG) ;;
  l) KEYLEN="$OPTARG" ;;
  c) SRC_CERT="$OPTARG" ;;
  k) SRC_KEY="$OPTARG" ;;
  x) CA_CFG_PATH="$OPTARG" ;;
  m) MAXENROLL="$OPTARG" ;;
  g) SERVERCONFIG="$OPTARG" ;;
  U) PARENTURL="$OPTARG" ;;
  D) export FABRIC_CA_DEBUG='true' ;;
  A) AUTH="false" ;;
  R) RESET="true" ;;
  I) INIT="true" ;;
  S) START="true" ;;
  X) PROXY="true" ;;
  K) KILL="true" ;;
  L) LIST="true" ;;
  P) export FABRIC_CA_SERVER_PROFILE_PORT=$PROFILING_PORT ;;
  N) export FABRIC_CA_INTERMEDIATE_SERVER_PORT=$INTERMEDIATE_CA_DEFAULT_PORT ;;
  \? | h)
    usage
    exit 1
    ;;
  esac
done

shift $((OPTIND - 1))
args=$@
: ${LDAP_ENABLE:="false"}
: ${TIMEOUT:=$DEFAULT_TIMEOUT}
: ${HTTP_PORT:="3755"}
: ${DBNAME:="fabric_ca"}
: ${MAXENROLL:="-1"}
: ${AUTH:="true"}
: ${DRIVER:="sqlite3"}
: ${FABRIC_CA_INSTANCES:=1}
: ${FABRIC_CA_DEBUG:="false"}
: ${LIST:="false"}
: ${RESET:="false"}
: ${INIT:="false"}
: ${START:="false"}
: ${PROXY:="false"}
: ${HTTP:="true"}
: ${KILL:="false"}
: ${KEYTYPE:="ecdsa"}
: ${KEYLEN:="256"}
: ${CACOUNT=""}
test $KEYTYPE = "rsa" && SSLKEYCMD=$KEYTYPE || SSLKEYCMD="ec"
test -n "$PARENTURL" && PARENTURL="-u $PARENTURL"

: ${CA_CFG_PATH:="/tmp/fabric-ca"}
: ${DATADIR:="$CA_CFG_PATH"}
export CA_CFG_PATH

test -d $DATADIR || mkdir -p $DATADIR
DST_KEY="fabric-ca-key.pem"
DST_CERT="fabric-ca-cert.pem"
test -n "$SRC_CERT" && cp "$SRC_CERT" $DATADIR/$DST_CERT
test -n "$SRC_KEY" && cp "$SRC_KEY" $DATADIR/$DST_KEY
RUNCONFIG="$DATADIR/$DEFAULT_RUN_CONFIG_FILE_NAME"

case $DRIVER in
postgres) DATASRC="dbname=$DBNAME host=127.0.0.1 port=$POSTGRES_PORT user=postgres password=postgres" ;;
sqlite3) DATASRC="$DBNAME" ;;
mysql) DATASRC="root:mysql@tcp(localhost:$MYSQL_PORT)/$DBNAME?parseTime=true" ;;
esac

$($LIST) && listFabricCa
$($RESET) && resetFabricCa
$($KILL) && killAllFabricCas
$($PROXY) && startHaproxy $FABRIC_CA_INSTANCES

$($INIT -o $START) && genRunconfig "$RUNCONFIG" "$DRIVER" "$DATASRC" "$DST_CERT" "$DST_KEY" "$MAXENROLL"
test -n "$SERVERCONFIG" && cp "$SERVERCONFIG" "$RUNCONFIG"

if $($INIT); then
  initFabricCa
  rc2=$?
  if test $rc2 -eq 1; then
    exit $rc2
  fi
fi

if $($START); then
  inst=0
  while test $((inst)) -lt $FABRIC_CA_INSTANCES; do
    startFabricCa $inst
    inst=$((inst + 1))
  done
fi
exit $RC
