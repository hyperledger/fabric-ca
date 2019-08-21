.. code:: yaml

   version: '2'

   networks:
   fabric-ca:

   services:
   ca-tls:
      container_name: ca-tls
      image: hyperledger/fabric-ca:1.4.0
      command: sh -c 'fabric-ca-server start -d -b tls-ca-admin:tls-ca-adminpw --port 7052'
      environment:
         - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca/crypto
         - FABRIC_CA_SERVER_CSR_CN=tls-ca
         - FABRIC_CA_SERVER_CSR_HOSTS=0.0.0.0
         - FABRIC_CA_SERVER_DEBUG=true
      volumes:
         - /tmp/hyperledger/tls-ca:/tmp/hyperledger/fabric-ca
      networks:
         - fabric-ca
      ports:
         - 7052:7052

   rca-org0:
      container_name: rca-org0
      image: hyperledger/fabric-ca:1.4.0
      command: sh -c 'fabric-ca-server start -d -b rca-org0-admin:rca-org0-adminpw --port 7053'
      environment:
         - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca/crypto
         - FABRIC_CA_SERVER_TLS_ENABLED=true
         - FABRIC_CA_SERVER_CSR_CN=rca-org0
         - FABRIC_CA_SERVER_CSR_HOSTS=0.0.0.0
         - FABRIC_CA_SERVER_DEBUG=true
      volumes:
         - /tmp/hyperledger/org0/ca:/tmp/hyperledger/fabric-ca
      networks:
         - fabric-ca
      ports:
         - 7053:7053

   rca-org1:
      container_name: rca-org1
      image: hyperledger/fabric-ca:1.4.0
      command: sh -c 'fabric-ca-server start -d -b rca-org1-admin:rca-org1-adminpw --port 7054'
      environment:
         - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca/crypto
         - FABRIC_CA_SERVER_TLS_ENABLED=true
         - FABRIC_CA_SERVER_CSR_CN=rca-org1
         - FABRIC_CA_SERVER_CSR_HOSTS=0.0.0.0
         - FABRIC_CA_SERVER_DEBUG=true
      volumes:
         - /tmp/hyperledger/org1/ca:/tmp/hyperledger/fabric-ca
      networks:
         - fabric-ca
      ports:
         - 7054:7054

   rca-org2:
      container_name: rca-org2
      image: hyperledger/fabric-ca:1.4.0
      command: /bin/bash -c 'fabric-ca-server start -d -b rca-org2-admin:rca-org2-adminpw --port 7055'
      environment:
         - FABRIC_CA_SERVER_HOME=/tmp/hyperledger/fabric-ca/crypto
         - FABRIC_CA_SERVER_TLS_ENABLED=true
         - FABRIC_CA_SERVER_CSR_CN=rca-org2
         - FABRIC_CA_SERVER_CSR_HOSTS=0.0.0.0
         - FABRIC_CA_SERVER_DEBUG=true
      volumes:
         - /tmp/hyperledger/org2/ca:/tmp/hyperledger/fabric-ca
      networks:
         - fabric-ca
      ports:
         - 7055:7055

   peer1-org1:
      container_name: peer1-org1
      image: hyperledger/fabric-peer:1.4.0
      environment:
         - CORE_PEER_ID=peer1-org1
         - CORE_PEER_ADDRESS=peer1-org1:7051
         - CORE_PEER_LOCALMSPID=org1MSP
         - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org1/peer1/msp
         - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
         - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
         - FABRIC_LOGGING_SPEC=debug
         - CORE_PEER_TLS_ENABLED=true
         - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org1/peer1/tls-msp/signcerts/cert.pem
         - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org1/peer1/tls-msp/keystore/key.pem
         - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org1/peer1/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
         - CORE_PEER_GOSSIP_USELEADERELECTION=true
         - CORE_PEER_GOSSIP_ORGLEADER=false
         - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer1-org1:7051
         - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
      working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org1/peer1
      volumes:
         - /var/run:/host/var/run
         - /tmp/hyperledger/org1/peer1:/tmp/hyperledger/org1/peer1
      networks:
         - fabric-ca

   peer2-org1:
      container_name: peer2-org1
      image: hyperledger/fabric-peer:1.4.0
      environment:
         - CORE_PEER_ID=peer2-org1
         - CORE_PEER_ADDRESS=peer2-org1:7051
         - CORE_PEER_LOCALMSPID=org1MSP
         - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org1/peer2/msp
         - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
         - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
         - FABRIC_LOGGING_SPEC=grpc=debug:info
         - CORE_PEER_TLS_ENABLED=true
         - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org1/peer2/tls-msp/signcerts/cert.pem
         - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org1/peer2/tls-msp/keystore/key.pem
         - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org1/peer2/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
         - CORE_PEER_GOSSIP_USELEADERELECTION=true
         - CORE_PEER_GOSSIP_ORGLEADER=false
         - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer2-org1:7051
         - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
         - CORE_PEER_GOSSIP_BOOTSTRAP=peer1-org1:7051
      working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org1/peer2
      volumes:
         - /var/run:/host/var/run
         - /tmp/hyperledger/org1/peer2:/tmp/hyperledger/org1/peer2
      networks:
         - fabric-ca

   peer1-org2:
      container_name: peer1-org2
      image: hyperledger/fabric-peer:1.4.0
      environment:
         - CORE_PEER_ID=peer1-org2
         - CORE_PEER_ADDRESS=peer1-org2:7051
         - CORE_PEER_LOCALMSPID=org2MSP
         - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org2/peer1/msp
         - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
         - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
         - FABRIC_LOGGING_SPEC=debug
         - CORE_PEER_TLS_ENABLED=true
         - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org2/peer1/tls-msp/signcerts/cert.pem
         - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org2/peer1/tls-msp/keystore/key.pem
         - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org2/peer1/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
         - CORE_PEER_GOSSIP_USELEADERELECTION=true
         - CORE_PEER_GOSSIP_ORGLEADER=false
         - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer1-org2:7051
         - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
      working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org2/peer1
      volumes:
         - /var/run:/host/var/run
         - /tmp/hyperledger/org2/peer1:/tmp/hyperledger/org2/peer1
      networks:
         - fabric-ca

   peer2-org2:
      container_name: peer2-org2
      image: hyperledger/fabric-peer:1.4.0
      environment:
         - CORE_PEER_ID=peer2-org2
         - CORE_PEER_ADDRESS=peer2-org2:7051
         - CORE_PEER_LOCALMSPID=org2MSP
         - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org2/peer2/msp
         - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
         - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=guide_fabric-ca
         - FABRIC_LOGGING_SPEC=debug
         - CORE_PEER_TLS_ENABLED=true
         - CORE_PEER_TLS_CERT_FILE=/tmp/hyperledger/org2/peer2/tls-msp/signcerts/cert.pem
         - CORE_PEER_TLS_KEY_FILE=/tmp/hyperledger/org2/peer2/tls-msp/keystore/key.pem
         - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org2/peer2/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
         - CORE_PEER_GOSSIP_USELEADERELECTION=true
         - CORE_PEER_GOSSIP_ORGLEADER=false
         - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer2-org2:7051
         - CORE_PEER_GOSSIP_SKIPHANDSHAKE=true
         - CORE_PEER_GOSSIP_BOOTSTRAP=peer1-org2:7051
      working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org2/peer2
      volumes:
         - /var/run:/host/var/run
         - /tmp/hyperledger/org2/peer2:/tmp/hyperledger/org2/peer2
      networks:
         - fabric-ca

   orderer1-org0:
      container_name: orderer1-org0
      image: hyperledger/fabric-orderer:1.4.0
      environment:
         - ORDERER_HOME=/tmp/hyperledger/orderer
         - ORDERER_HOST=orderer1-org0
         - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
         - ORDERER_GENERAL_GENESISMETHOD=file
         - ORDERER_GENERAL_GENESISFILE=/tmp/hyperledger/org0/orderer/genesis.block
         - ORDERER_GENERAL_LOCALMSPID=org0MSP
         - ORDERER_GENERAL_LOCALMSPDIR=/tmp/hyperledger/org0/orderer/msp
         - ORDERER_GENERAL_TLS_ENABLED=true
         - ORDERER_GENERAL_TLS_CERTIFICATE=/tmp/hyperledger/org0/orderer/tls-msp/signcerts/cert.pem
         - ORDERER_GENERAL_TLS_PRIVATEKEY=/tmp/hyperledger/org0/orderer/tls-msp/keystore/key.pem
         - ORDERER_GENERAL_TLS_ROOTCAS=[/tmp/hyperledger/org0/orderer/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem]
         - ORDERER_GENERAL_LOGLEVEL=debug
         - ORDERER_DEBUG_BROADCASTTRACEDIR=data/logs
      volumes:
         - /tmp/hyperledger/org0/orderer:/tmp/hyperledger/org0/orderer/
      networks:
         - fabric-ca

   cli-org1:
      container_name: cli-org1
      image: hyperledger/fabric-tools:1.4.0
      tty: true
      stdin_open: true
      environment:
         - GOPATH=/opt/gopath
         - FABRIC_LOGGING_SPEC=DEBUG
         - CORE_PEER_ID=cli
         - CORE_PEER_ADDRESS=peer1-org1:7051
         - CORE_PEER_LOCALMSPID=org1MSP
         - CORE_PEER_TLS_ENABLED=true
         - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org1/peer1/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
         - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org1/peer1/msp
      working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org1
      command: sh
      volumes:
         - /tmp/hyperledger/org1/peer1:/tmp/hyperledger/org1/peer1
         - /tmp/hyperledger/org1/peer1/assets/chaincode:/opt/gopath/src/github.com/hyperledger/fabric-samples/chaincode
         - /tmp/hyperledger/org1/admin:/tmp/hyperledger/org1/admin
      networks:
         - fabric-ca
 
   cli-org2:
      container_name: cli-org2
      image: hyperledger/fabric-tools:1.4.0
      tty: true
      stdin_open: true
      environment:
         - GOPATH=/opt/gopath
         - FABRIC_LOGGING_SPEC=DEBUG
         - CORE_PEER_ID=cli
         - CORE_PEER_ADDRESS=peer1-org2:7051
         - CORE_PEER_LOCALMSPID=org2MSP
         - CORE_PEER_TLS_ENABLED=true
         - CORE_PEER_TLS_ROOTCERT_FILE=/tmp/hyperledger/org2/peer1/tls-msp/tlscacerts/tls-0-0-0-0-7052.pem
         - CORE_PEER_MSPCONFIGPATH=/tmp/hyperledger/org2/peer1/msp
      working_dir: /opt/gopath/src/github.com/hyperledger/fabric/org2
      command: sh
      volumes:
         - /tmp/hyperledger/org2/peer1:/tmp/hyperledger/org2/peer1
         - /tmp/hyperledger/org1/peer1/assets/chaincode:/opt/gopath/src/github.com/hyperledger/fabric-samples/chaincode
         - /tmp/hyperledger/org2/admin:/tmp/hyperledger/org2/admin
      networks:
         - fabric-ca
