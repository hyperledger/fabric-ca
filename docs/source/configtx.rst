.. code:: yaml

   ################################################################################
   #
   #   Section: Organizations
   #
   #   - This section defines the different organizational identities which will
   #   be referenced later in the configuration.
   #
   ################################################################################
   Organizations:

   - &org0

      Name: org0

      # ID to load the MSP definition as
      ID: org0MSP

      # MSPDir is the filesystem path which contains the MSP configuration
      MSPDir: /tmp/hyperledger/org0/msp

   - &org1

      Name: org1

      # ID to load the MSP definition as
      ID: org1MSP

      # MSPDir is the filesystem path which contains the MSP configuration
      MSPDir: /tmp/hyperledger/org1/msp

      AnchorPeers:
         # AnchorPeers defines the location of peers which can be used
         # for cross org gossip communication.  Note, this value is only
         # encoded in the genesis block in the Application section context
         - Host: peer1-org1
            Port: 7051

   - &org2

      Name: org2

      # ID to load the MSP definition as
      ID: org2MSP

      # MSPDir is the filesystem path which contains the MSP configuration
      MSPDir: /tmp/hyperledger/org2/msp

      AnchorPeers:
         # AnchorPeers defines the location of peers which can be used
         # for cross org gossip communication.  Note, this value is only
         # encoded in the genesis block in the Application section context
         - Host: peer1-org2
            Port: 7051

   ################################################################################
   #
   #   SECTION: Application
   #
   #   This section defines the values to encode into a config transaction or
   #   genesis block for application related parameters
   #
   ################################################################################
   Application: &ApplicationDefaults

      # Organizations is the list of orgs which are defined as participants on
      # the application side of the network
      Organizations:


   ################################################################################
   #
   #   Profile
   #
   #   - Different configuration profiles may be encoded here to be specified
   #   as parameters to the configtxgen tool
   #
   ################################################################################
   Profiles:

   OrgsOrdererGenesis:
      Orderer:
         # Orderer Type: The orderer implementation to start
         # Available types are "solo" and "kafka"
         OrdererType: solo
         Addresses:
         - orderer1-org0:7050

         # Batch Timeout: The amount of time to wait before creating a batch
         BatchTimeout: 2s

         # Batch Size: Controls the number of messages batched into a block
         BatchSize:

         # Max Message Count: The maximum number of messages to permit in a batch
         MaxMessageCount: 10

         # Absolute Max Bytes: The absolute maximum number of bytes allowed for
         # the serialized messages in a batch.
         AbsoluteMaxBytes: 99 MB

         # Preferred Max Bytes: The preferred maximum number of bytes allowed for
         # the serialized messages in a batch. A message larger than the preferred
         # max bytes will result in a batch larger than preferred max bytes.
         PreferredMaxBytes: 512 KB

         # Kafka:
         #   # Brokers: A list of Kafka brokers to which the orderer connects
         #   # NOTE: Use IP:port notation
         #   Brokers:
         #     - 127.0.0.1:9092

         # Organizations is the list of orgs which are defined as participants on
         # the orderer side of the network
         Organizations:
         - *org0

      Consortiums:

         SampleConsortium:

         Organizations:
            - *org1
            - *org2

   OrgsChannel:
      Consortium: SampleConsortium
      Application:
         <<: *ApplicationDefaults
         Organizations:
         - *org1
         - *org2

