## v1.0.0-alpha2
Fri May 12 15:29:02 EDT 2017


* [0650f04](https://github.com/hyperledger/fabric/commit/0650f04) [FAB-3895](https://jira.hyperledger.org/browse/FAB-3895) add scripts/changelog.sh
* [c1bb6c4](https://github.com/hyperledger/fabric/commit/c1bb6c4) [FAB-3574](https://jira.hyperledger.org/browse/FAB-3574) Fix missing CA config values logic
* [34ec53e](https://github.com/hyperledger/fabric/commit/34ec53e) [FAB-3574](https://jira.hyperledger.org/browse/FAB-3574) Perform deep copy of config file
* [2fa6143](https://github.com/hyperledger/fabric/commit/2fa6143) [FAB-3622](https://jira.hyperledger.org/browse/FAB-3622) Update API with JSON tag for 'CAName'
* [a010ec8](https://github.com/hyperledger/fabric/commit/a010ec8) [FAB-3629](https://jira.hyperledger.org/browse/FAB-3629) Move Fabric-CA doc to fabric-ca repo
* [0624550](https://github.com/hyperledger/fabric/commit/0624550) [FAB-3191](https://jira.hyperledger.org/browse/FAB-3191) Ability to enable cpu/heap profiling
* [15bc87e](https://github.com/hyperledger/fabric/commit/15bc87e) [ [FAB-1892](https://jira.hyperledger.org/browse/FAB-1892) ] - Add LDAP to fvt test image
* [90bd1b6](https://github.com/hyperledger/fabric/commit/90bd1b6) [ [FAB-3554](https://jira.hyperledger.org/browse/FAB-3554) ] Add make target for local CI tests
* [50bbfc7](https://github.com/hyperledger/fabric/commit/50bbfc7) [FAB-3050](https://jira.hyperledger.org/browse/FAB-3050) Document serial number of CSR
* [34ddbee](https://github.com/hyperledger/fabric/commit/34ddbee) [FAB-3433](https://jira.hyperledger.org/browse/FAB-3433) Short names for flags for revoke command
* [ecd796a](https://github.com/hyperledger/fabric/commit/ecd796a) [FAB-3518](https://jira.hyperledger.org/browse/FAB-3518) Fix fabric-ca-server build failure
* [50c540e](https://github.com/hyperledger/fabric/commit/50c540e) [FAB-3503](https://jira.hyperledger.org/browse/FAB-3503) Wrong MSP keystore directory location
* [610a3b9](https://github.com/hyperledger/fabric/commit/610a3b9) [ [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) ] revert blank CA name for tests
* [ab83a2e](https://github.com/hyperledger/fabric/commit/ab83a2e) [FAB-864](https://jira.hyperledger.org/browse/FAB-864) Vendor BCCSP from fabric to fabric-ca
* [0d272e6](https://github.com/hyperledger/fabric/commit/0d272e6) [FAB-2601](https://jira.hyperledger.org/browse/FAB-2601) Fabric CA BCCSP integration
* [9c4acfd](https://github.com/hyperledger/fabric/commit/9c4acfd) [FAB-2601](https://jira.hyperledger.org/browse/FAB-2601) Fabric CA BCCSP integration utilities
* [1583adf](https://github.com/hyperledger/fabric/commit/1583adf) [FAB-3369](https://jira.hyperledger.org/browse/FAB-3369) Added missing slice config options
* [5610d33](https://github.com/hyperledger/fabric/commit/5610d33) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Start multiple default CA instances
* [c131944](https://github.com/hyperledger/fabric/commit/c131944) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Directing traffic to specific CAs
* [d53f934](https://github.com/hyperledger/fabric/commit/d53f934) [FAB-3396](https://jira.hyperledger.org/browse/FAB-3396) Fixed "index out of range" error
* [3ab84cb](https://github.com/hyperledger/fabric/commit/3ab84cb) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Loading multiple CAs from config files
* [b4ce73f](https://github.com/hyperledger/fabric/commit/b4ce73f) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Create CA configuration struct
* [d7a5c29](https://github.com/hyperledger/fabric/commit/d7a5c29) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Support multiple CAs - new CA struct
* [8976d7b](https://github.com/hyperledger/fabric/commit/8976d7b) [ [FAB-1673](https://jira.hyperledger.org/browse/FAB-1673) ] Integrate fabric/cop fvt in CI
* [a13fc7c](https://github.com/hyperledger/fabric/commit/a13fc7c) [FAB-3107](https://jira.hyperledger.org/browse/FAB-3107) Use 'identity' instead of 'user'
* [c93266f](https://github.com/hyperledger/fabric/commit/c93266f) [FAB-2841](https://jira.hyperledger.org/browse/FAB-2841) Revoke fails if aki,serial and eid are set
* [4f472c4](https://github.com/hyperledger/fabric/commit/4f472c4) [FAB-2868](https://jira.hyperledger.org/browse/FAB-2868) Return 401 error for restricted operations
* [2672dd3](https://github.com/hyperledger/fabric/commit/2672dd3) [ [FAB-2909](https://jira.hyperledger.org/browse/FAB-2909) ] Fix failing UT for file name too long
* [75f402c](https://github.com/hyperledger/fabric/commit/75f402c) [FAB-1463](https://jira.hyperledger.org/browse/FAB-1463) Add TLS support to CA server's LDAP client
* [5dd0561](https://github.com/hyperledger/fabric/commit/5dd0561) [FAB-2597](https://jira.hyperledger.org/browse/FAB-2597) Del cfssl prefix from REST APIs
* [7539e33](https://github.com/hyperledger/fabric/commit/7539e33) [FAB-2955](https://jira.hyperledger.org/browse/FAB-2955) Set max open conn for sqlite to 1
* [6d5ae41](https://github.com/hyperledger/fabric/commit/6d5ae41) [FAB-3061](https://jira.hyperledger.org/browse/FAB-3061) Persist the ca.name
* [de5f4bd](https://github.com/hyperledger/fabric/commit/de5f4bd) [FAB-3174](https://jira.hyperledger.org/browse/FAB-3174) Fix compile error in tls.go
* [7b356c9](https://github.com/hyperledger/fabric/commit/7b356c9) [FAB-1854](https://jira.hyperledger.org/browse/FAB-1854) Add file names with colons to gitignore
* [7f85469](https://github.com/hyperledger/fabric/commit/7f85469) Handle string slices in config appropriately
* [1c68d07](https://github.com/hyperledger/fabric/commit/1c68d07) [FAB-1467](https://jira.hyperledger.org/browse/FAB-1467) Allow make without docker
* [f0f86b7](https://github.com/hyperledger/fabric/commit/f0f86b7) Client should check TLS cert for valid dates
* [b31da6b](https://github.com/hyperledger/fabric/commit/b31da6b) Fix affiliation hierarchy checking during revoke
* [db76a08](https://github.com/hyperledger/fabric/commit/db76a08) [FAB-3004](https://jira.hyperledger.org/browse/FAB-3004) Remove extraneous flags
* [7a4a7f4](https://github.com/hyperledger/fabric/commit/7a4a7f4) [FAB-3038](https://jira.hyperledger.org/browse/FAB-3038) Fix certificate look up logic
* [4c3189b](https://github.com/hyperledger/fabric/commit/4c3189b) [FAB-3007](https://jira.hyperledger.org/browse/FAB-3007):Make CA name required
* [855036c](https://github.com/hyperledger/fabric/commit/855036c) [FAB-3010](https://jira.hyperledger.org/browse/FAB-3010) Update the fabric-ca README
* [ee2ec59](https://github.com/hyperledger/fabric/commit/ee2ec59) [FAB-2668](https://jira.hyperledger.org/browse/FAB-2668) Ensure revocation updates DB
* [d9a1724](https://github.com/hyperledger/fabric/commit/d9a1724) [FAB-3020](https://jira.hyperledger.org/browse/FAB-3020) fix client-server-flow doc typo
* [a8f1d79](https://github.com/hyperledger/fabric/commit/a8f1d79) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Update enrollment test
* [e909700](https://github.com/hyperledger/fabric/commit/e909700) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Update roundrobin test
* [05cbac8](https://github.com/hyperledger/fabric/commit/05cbac8) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Update reregister test
* [7b9eb18](https://github.com/hyperledger/fabric/commit/7b9eb18) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) - Update reenroll test
* [bfacafe](https://github.com/hyperledger/fabric/commit/bfacafe) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) - Update group test
* [4456f65](https://github.com/hyperledger/fabric/commit/4456f65) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) - Remove local install of fabric prereq
* [06bb12f](https://github.com/hyperledger/fabric/commit/06bb12f) [FAB-2572](https://jira.hyperledger.org/browse/FAB-2572) Update client/server TLS setting
* [20a1b7a](https://github.com/hyperledger/fabric/commit/20a1b7a) [FAB-](https://jira.hyperledger.org/browse/FAB-)[2571] use variable database name
* [4997ae7](https://github.com/hyperledger/fabric/commit/4997ae7) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Generate config for both init and start
* [5a07ff7](https://github.com/hyperledger/fabric/commit/5a07ff7) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Change client/server executable names
* [d10fd42](https://github.com/hyperledger/fabric/commit/d10fd42) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Create docker image for fvt testing
* [54a8729](https://github.com/hyperledger/fabric/commit/54a8729) Delete obsolete authentication test
* [f6fc6e8](https://github.com/hyperledger/fabric/commit/f6fc6e8) Update run_ldap library directory for [FAB-1485](https://jira.hyperledger.org/browse/FAB-1485)
* [bd594b5](https://github.com/hyperledger/fabric/commit/bd594b5) Failing util_test.go -- need to unset CA_CFG_PATH
* [a64ea74](https://github.com/hyperledger/fabric/commit/a64ea74) Don't print usage message for non-usage errors
* [055cdc5](https://github.com/hyperledger/fabric/commit/055cdc5) Improvement to TLS configurations
* [4651512](https://github.com/hyperledger/fabric/commit/4651512) [FAB-2866](https://jira.hyperledger.org/browse/FAB-2866): Export new and load Identity methods
* [2b9daa3](https://github.com/hyperledger/fabric/commit/2b9daa3) Case sensitivity for MySQL users table
* [e9bc7ff](https://github.com/hyperledger/fabric/commit/e9bc7ff) Revoked user should not be able to make requests
* [684e63e](https://github.com/hyperledger/fabric/commit/684e63e) Fix [FAB-1485](https://jira.hyperledger.org/browse/FAB-1485)
* [fb3a4a9](https://github.com/hyperledger/fabric/commit/fb3a4a9) Prepare for post-alpha development
* [2360c26](https://github.com/hyperledger/fabric/commit/2360c26) Fix init information in config.go
* [4325538](https://github.com/hyperledger/fabric/commit/4325538) Rename occurences of COP to CA

## v1.0.0-alpha 
March 16, 2017

* [b587a48](https://github.com/hyperledger/fabric/commit/b587a48) Release v1.0.0-alpha
* [382c65b](https://github.com/hyperledger/fabric/commit/382c65b) BCCSP InitFactories not called in fabric-ca-client
* [9132e6d](https://github.com/hyperledger/fabric/commit/9132e6d) Client home has incorrect path when env vars set
* [12b0e1b](https://github.com/hyperledger/fabric/commit/12b0e1b) Do not restrict fabric-ca client config to yml
* [46bbd8c](https://github.com/hyperledger/fabric/commit/46bbd8c) enroll req sent with an invalid auth header should fail
* [cb9fae9](https://github.com/hyperledger/fabric/commit/cb9fae9) Fix linting error with lib/server.go
* [e183a88](https://github.com/hyperledger/fabric/commit/e183a88) Changes to make auth type an enum
* [808a15d](https://github.com/hyperledger/fabric/commit/808a15d) Affiliation table clean up
* [c7b482e](https://github.com/hyperledger/fabric/commit/c7b482e) Add support for -M option for enroll/reenroll
* [2e51747](https://github.com/hyperledger/fabric/commit/2e51747) Add support for client getcacert command
* [074ebab](https://github.com/hyperledger/fabric/commit/074ebab) Mask passwords in the log entries
* [b09448e](https://github.com/hyperledger/fabric/commit/b09448e) Tests to check db file is created in right dir
* [df922a1](https://github.com/hyperledger/fabric/commit/df922a1) Remove global variables in lib
* [ee4f92a](https://github.com/hyperledger/fabric/commit/ee4f92a) Remove cli from fabric-ca
* [403080d](https://github.com/hyperledger/fabric/commit/403080d) Improvements to revoke client side command
* [cd8802b](https://github.com/hyperledger/fabric/commit/cd8802b) Registrar can configure max enrollment for user
* [35c5648](https://github.com/hyperledger/fabric/commit/35c5648) Replace group with affiliation for users
* [7c44a8f](https://github.com/hyperledger/fabric/commit/7c44a8f) Enrollment info part of client config
* [4d9e2e3](https://github.com/hyperledger/fabric/commit/4d9e2e3) Registration request part of client config
* [c2bd335](https://github.com/hyperledger/fabric/commit/c2bd335) Vendor fetch bccsp from fabric
* [9195741](https://github.com/hyperledger/fabric/commit/9195741) TLS testcases and process file names client config
* [64e22bd](https://github.com/hyperledger/fabric/commit/64e22bd) Base 64 encode/decode with padding
* [c3d00c3](https://github.com/hyperledger/fabric/commit/c3d00c3) [FAB-2481](https://jira.hyperledger.org/browse/FAB-2481) cleanup files with suspicious permissions
* [87410b4](https://github.com/hyperledger/fabric/commit/87410b4) Update fabric-ca-server UT main test
* [34ad615](https://github.com/hyperledger/fabric/commit/34ad615) Docker image with client and server commands
* [3f8445a](https://github.com/hyperledger/fabric/commit/3f8445a) Intermediate CA server support
* [d02bbe4](https://github.com/hyperledger/fabric/commit/d02bbe4) Reflect to add server config flags
* [9ae96f2](https://github.com/hyperledger/fabric/commit/9ae96f2) Revendor cfssl for fabricc-ca BCCSP integration
* [c280fa3](https://github.com/hyperledger/fabric/commit/c280fa3) Fabric-CA bccsp integration for VerifyToken
* [98abc75](https://github.com/hyperledger/fabric/commit/98abc75) Fix README.md
* [3ab50fc](https://github.com/hyperledger/fabric/commit/3ab50fc) Pre-req for fabric-ca/fvt-test.
* [37b897b](https://github.com/hyperledger/fabric/commit/37b897b) fabric-ca-client commands for cobra/viper CLI
* [fbccd13](https://github.com/hyperledger/fabric/commit/fbccd13) Complete fabric-ca-server start command
* [9db14ab](https://github.com/hyperledger/fabric/commit/9db14ab) Added revocation test
* [ee8ccef](https://github.com/hyperledger/fabric/commit/ee8ccef) Added test for command line default port/addr
* [67c9491](https://github.com/hyperledger/fabric/commit/67c9491) Add certificate validation test
* [41e6c52](https://github.com/hyperledger/fabric/commit/41e6c52) Fix README.md
* [0243300](https://github.com/hyperledger/fabric/commit/0243300) Add version-agnostic link to DB executable
* [2ff7ba5](https://github.com/hyperledger/fabric/commit/2ff7ba5) Added docker-compose for running fvt tests
* [5a35b72](https://github.com/hyperledger/fabric/commit/5a35b72) fabric-ca-server start for cobra/viper CLI
* [5f56827](https://github.com/hyperledger/fabric/commit/5f56827) fabric-ca-server init command
* [33547ef](https://github.com/hyperledger/fabric/commit/33547ef) Update swagger doc for fabric-ca server's APIs
* [f507e2d](https://github.com/hyperledger/fabric/commit/f507e2d) Fix the config path env variable
* [c4e83c1](https://github.com/hyperledger/fabric/commit/c4e83c1) fabric-ca-client command plumbing with cobra/viper
* [b0e45f5](https://github.com/hyperledger/fabric/commit/b0e45f5) fabric-ca-server command plumbing with cobra/viper
* [1ec55b2](https://github.com/hyperledger/fabric/commit/1ec55b2) Vendor cobra to use in fabric-ca CLI work
* [3b781fb](https://github.com/hyperledger/fabric/commit/3b781fb) Added test for registrar delgation
* [5105f60](https://github.com/hyperledger/fabric/commit/5105f60) COP Client Configuration File
* [6294c57](https://github.com/hyperledger/fabric/commit/6294c57) Remove the fabric-ca docker directory
* [9fde6f4](https://github.com/hyperledger/fabric/commit/9fde6f4) Added support for TLS; deleted trailing spaces
* [d8d192e](https://github.com/hyperledger/fabric/commit/d8d192e) Directory restructure for Change 4383
* [daf28ad](https://github.com/hyperledger/fabric/commit/daf28ad) Create swagger json for fabric-ca REST APIs
* [2ccb6d3](https://github.com/hyperledger/fabric/commit/2ccb6d3) Fabric-CA throws NPE using config file to start
* [ffe7676](https://github.com/hyperledger/fabric/commit/ffe7676) Added basic fvt tests and utilities
* [8511358](https://github.com/hyperledger/fabric/commit/8511358) Fix overlooked rename to fabric-ca
* [05b0f1d](https://github.com/hyperledger/fabric/commit/05b0f1d) [FAB-1652](https://jira.hyperledger.org/browse/FAB-1652) Use fabric-baseos instead of busybox
* [da88926](https://github.com/hyperledger/fabric/commit/da88926) Remove errant .gitignore exclusion of "fabric-ca"
* [585467a](https://github.com/hyperledger/fabric/commit/585467a) Remove references to cop from README
* [f5291e7](https://github.com/hyperledger/fabric/commit/f5291e7) Change expose port in dockerfile from 8888 to 7054
* [a569df9](https://github.com/hyperledger/fabric/commit/a569df9) Change the default port to 7054
* [aa5fb82](https://github.com/hyperledger/fabric/commit/aa5fb82) Revendor fabric's bccsp into fabric-ca
* [79a2558](https://github.com/hyperledger/fabric/commit/79a2558) [FAB-1338](https://jira.hyperledger.org/browse/FAB-1338): Fix configs after rename
* [606fbdc](https://github.com/hyperledger/fabric/commit/606fbdc) COP BCCSP integration
* [8894989](https://github.com/hyperledger/fabric/commit/8894989) Renaming from fabric-cop to fabric-ca
* [c676b70](https://github.com/hyperledger/fabric/commit/c676b70) [FAB-1338](https://jira.hyperledger.org/browse/FAB-1338): Include all config and cert files
* [00fc126](https://github.com/hyperledger/fabric/commit/00fc126) Fix util test to pass on Windows
* [bac392b](https://github.com/hyperledger/fabric/commit/bac392b) Make sure cop.db is systematically deleted for testing.
* [88866f1](https://github.com/hyperledger/fabric/commit/88866f1) Delete cop.db after running COP unit tests
* [4e6481c](https://github.com/hyperledger/fabric/commit/4e6481c) COP UserRegistry Consolidation
* [1ee390f](https://github.com/hyperledger/fabric/commit/1ee390f) Fix linting error
* [81097b9](https://github.com/hyperledger/fabric/commit/81097b9) COP API simplification
* [ebb62e9](https://github.com/hyperledger/fabric/commit/ebb62e9) The reenroll command is incorrect in README
* [f0af10a](https://github.com/hyperledger/fabric/commit/f0af10a) Fix incorrect license header
* [a9ff4d4](https://github.com/hyperledger/fabric/commit/a9ff4d4) Store COP enrollment artifacts in MSP friendly way
* [8a95c35](https://github.com/hyperledger/fabric/commit/8a95c35) Added missing CONTRIBUTING and MAINTAINERS files
* [e1fbfbf](https://github.com/hyperledger/fabric/commit/e1fbfbf) Improve docker build/experience
* [a5666ff](https://github.com/hyperledger/fabric/commit/a5666ff) Process file names in config file correctly
* [8e0b628](https://github.com/hyperledger/fabric/commit/8e0b628) [FAB-1546](https://jira.hyperledger.org/browse/FAB-1546)"make ldap-tests" fails due to test code bug
* [72a87e3](https://github.com/hyperledger/fabric/commit/72a87e3) Enforce validity period in COP for ECerts/TCerts
* [718647e](https://github.com/hyperledger/fabric/commit/718647e) Clean up Config structure
* [35a1f13](https://github.com/hyperledger/fabric/commit/35a1f13) Integrate TCert library into COP server and client
* [923148b](https://github.com/hyperledger/fabric/commit/923148b) Complete step 2 of cop client revoke work
* [6fc7615](https://github.com/hyperledger/fabric/commit/6fc7615) Add support for TLS and config file enhanced
* [c11e7f4](https://github.com/hyperledger/fabric/commit/c11e7f4) More tcert library APIs prior to COP integration
* [bdea0cf](https://github.com/hyperledger/fabric/commit/bdea0cf) [FAB-1470](https://jira.hyperledger.org/browse/FAB-1470) Fix docker-clean Makefile target
* [776c117](https://github.com/hyperledger/fabric/commit/776c117) Add .gitreview
* [8ede0e0](https://github.com/hyperledger/fabric/commit/8ede0e0) Remove duplicated test data
* [f1a894a](https://github.com/hyperledger/fabric/commit/f1a894a) Add command instruction to Makefile
* [4526770](https://github.com/hyperledger/fabric/commit/4526770) Address [FAB-1454](https://jira.hyperledger.org/browse/FAB-1454) add docker image for fabric-cop
* [4bd06ec](https://github.com/hyperledger/fabric/commit/4bd06ec) Adding TCert Library API
* [17abd20](https://github.com/hyperledger/fabric/commit/17abd20) Extend CFSSL accessor to support ID in Cert table
* [5802e29](https://github.com/hyperledger/fabric/commit/5802e29) Add shebang to run_ldap_tests sctipt
* [ed2ad83](https://github.com/hyperledger/fabric/commit/ed2ad83) Crypto Support for TCert
* [a7432e4](https://github.com/hyperledger/fabric/commit/a7432e4) Documentation fix README.md
* [32cba00](https://github.com/hyperledger/fabric/commit/32cba00) Add LDAP support to COP server
* [690c33c](https://github.com/hyperledger/fabric/commit/690c33c) Group Prekey, Serial Number, and Max Enrollments
* [d88fd4a](https://github.com/hyperledger/fabric/commit/d88fd4a) [FAB-1214](https://jira.hyperledger.org/browse/FAB-1214): Generates a fabric-cop image for docker
* [7efaab6](https://github.com/hyperledger/fabric/commit/7efaab6) Abstract DB and enable plugging in LDAP
* [de5918d](https://github.com/hyperledger/fabric/commit/de5918d) Run the COP server in a cluster (MySQL)
* [dccf180](https://github.com/hyperledger/fabric/commit/dccf180) Run the COP server in a cluster (Postgres)
* [ba8ff6e](https://github.com/hyperledger/fabric/commit/ba8ff6e) Vendor BCCSP from FABRIC into FABRIC-COP
* [90bd09f](https://github.com/hyperledger/fabric/commit/90bd09f) Copy/modify cfssl serve.go
* [ffb4fc2](https://github.com/hyperledger/fabric/commit/ffb4fc2) Add support for certificate revocation
* [84328df](https://github.com/hyperledger/fabric/commit/84328df) Add support for cop client reenroll
* [66cd46d](https://github.com/hyperledger/fabric/commit/66cd46d) fix code coverage report issue
* [1114d56](https://github.com/hyperledger/fabric/commit/1114d56) Add database config as part of server config
* [ec34a1d](https://github.com/hyperledger/fabric/commit/ec34a1d) [FAB-449](https://jira.hyperledger.org/browse/FAB-449) with updated README.md: cop server init CSRJSON
* [46ce6be](https://github.com/hyperledger/fabric/commit/46ce6be) Improve COP CLI error messages
* [9ccf04a](https://github.com/hyperledger/fabric/commit/9ccf04a) [FAB-1015](https://jira.hyperledger.org/browse/FAB-1015) code coverage report for fabric-cop repository
* [33fa279](https://github.com/hyperledger/fabric/commit/33fa279) Testcases added to support better test coverage
* [3ef8656](https://github.com/hyperledger/fabric/commit/3ef8656) Added license headers
* [a264a94](https://github.com/hyperledger/fabric/commit/a264a94) Initial COP impl of IDP APIs
* [ffa64c8](https://github.com/hyperledger/fabric/commit/ffa64c8) Add Identity Provider APIs
* [df3844d](https://github.com/hyperledger/fabric/commit/df3844d) Initial COP checkin

