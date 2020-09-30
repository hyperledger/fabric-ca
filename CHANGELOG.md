## v1.4.9
Wed Sep 30 14:48:49 EDT 2020

* [e709511](https://github.com/hyperledger/fabric-ca/commit/e709511) Add v1.4.9 release notes.
* [8ac7348](https://github.com/hyperledger/fabric-ca/commit/8ac7348) Allow reenroll to reuse existing private key
* [4d53ed8](https://github.com/hyperledger/fabric-ca/commit/4d53ed8) Edits to use a CA

## v1.4.8
Thu Jul 30 20:04:06 EDT 2020

* [c4ef033](https://github.com/hyperledger/fabric-ca/commit/c4ef033) Rel notes v1.4.8
* [146b8be](https://github.com/hyperledger/fabric-ca/commit/146b8be) Bump Go to 1.13.12
* [f8b233c](https://github.com/hyperledger/fabric-ca/commit/f8b233c) Move StartNonceSweeper out of NonceManager constructor (bp #181) (#182)
* [b6aa376](https://github.com/hyperledger/fabric-ca/commit/b6aa376) [FABC-912] Remove label and pin from logs
* [f96ceb9](https://github.com/hyperledger/fabric-ca/commit/f96ceb9) Fix the indentation in the NodeOU source code
* [b10a159](https://github.com/hyperledger/fabric-ca/commit/b10a159) [FAB-17702](https://jira.hyperledger.org/browse/FAB-17702) Use a CA
* [fcda8bb](https://github.com/hyperledger/fabric-ca/commit/fcda8bb) [FABC-829] Add hf.AffiliationMgr and hf.GenCRL attributes to migrated (#159)
* [f9a3427](https://github.com/hyperledger/fabric-ca/commit/f9a3427) Prepare for Fabric CA v1.4.8

## v1.4.7
Thu May 14 12:48:59 EDT 2020

* [a891700](https://github.com/hyperledger/fabric-ca/commit/a891700) Release Fabric CA v1.4.7
* [c1e4403](https://github.com/hyperledger/fabric-ca/commit/c1e4403) [FAB-17438](https://jira.hyperledger.org/browse/FAB-17438) Fabric CA Deployment Guide
* [287ea31](https://github.com/hyperledger/fabric-ca/commit/287ea31) Add operations guide to the toc in the release-1.4  branch
* [0a6179f](https://github.com/hyperledger/fabric-ca/commit/0a6179f) Add support for .md files and variable replacement in /docs
* [56e16da](https://github.com/hyperledger/fabric-ca/commit/56e16da) [FABC-904] Add Version Endpoint
* [1dcf373](https://github.com/hyperledger/fabric-ca/commit/1dcf373) Back port Operations Guide to release-1.4 branch
* [47c3854](https://github.com/hyperledger/fabric-ca/commit/47c3854) Move AZP file to correct place
* [03f35b4](https://github.com/hyperledger/fabric-ca/commit/03f35b4) [FABC-907] Update Go to 1.13
* [5c1b961](https://github.com/hyperledger/fabric-ca/commit/5c1b961) Replace LabelHelp with info in doc template
* [15d676f](https://github.com/hyperledger/fabric-ca/commit/15d676f) Add metrics doc generation to docs make target
* [a4e6a01](https://github.com/hyperledger/fabric-ca/commit/a4e6a01) Pin fabric dependencies to specific releases
* [789f83c](https://github.com/hyperledger/fabric-ca/commit/789f83c) Cleanup vendor.json and bring in bccsp from 1.4
* [5616f18](https://github.com/hyperledger/fabric-ca/commit/5616f18) Update release make targets
* [505df12](https://github.com/hyperledger/fabric-ca/commit/505df12) Remove call to InitFactories (#108)
* [4e2a19a](https://github.com/hyperledger/fabric-ca/commit/4e2a19a) Prepare for fabric-ca v1.4.7

## v1.4.6
Tue Feb 25 12:48:07 EST 2020

* [8d3a701](https://github.com/hyperledger/fabric-ca/commit/8d3a701) Update Release notes for 1.4.6
* [2799a7b](https://github.com/hyperledger/fabric-ca/commit/2799a7b) Update sqlite3 dependency and simplify release target
* [ce91e5d](https://github.com/hyperledger/fabric-ca/commit/ce91e5d) Release fabric-ca v1.4.6
* [c00700f](https://github.com/hyperledger/fabric-ca/commit/c00700f) Prepare for next fabric-ca release v1.4.6

## v1.4.5
Wed Feb 19 13:13:12 EST 2020

* [93f6863](https://github.com/hyperledger/fabric-ca/commit/93f6863) Support reading Operations TLS settings from file
* [a891cd1](https://github.com/hyperledger/fabric-ca/commit/a891cd1) [FABC-891] Create missing index on postgres db
* [e3fd520](https://github.com/hyperledger/fabric-ca/commit/e3fd520) [FABC-890] Fix responses in swagger.json
* [292781e](https://github.com/hyperledger/fabric-ca/commit/292781e) FABC-806 Do not honor client expiry request
* [a3c0171](https://github.com/hyperledger/fabric-ca/commit/a3c0171) [FAB-17074](https://jira.hyperledger.org/browse/FAB-17074) Prepare for next fabric-ca rel v1.4.5

## v1.4.4
Thu Nov 14 14:40:24 EST 2019

* [5675315](https://github.com/hyperledger/fabric-ca/commit/5675315) Add fabric-ca release notes v1.4.4
* [7302172](https://github.com/hyperledger/fabric-ca/commit/7302172) [FABC-884] Upgrade to go 1.12
* [5ffb381](https://github.com/hyperledger/fabric-ca/commit/5ffb381) FABC-873 remove invalid test
* [e9b3492](https://github.com/hyperledger/fabric-ca/commit/e9b3492) [FABC-844] address vet issues
* [1559aa3](https://github.com/hyperledger/fabric-ca/commit/1559aa3) FABC-881 Use earlier revision of bccsp
* [3b8a5c7](https://github.com/hyperledger/fabric-ca/commit/3b8a5c7) FABC-881 Update vendored dependencies
* [64c7d52](https://github.com/hyperledger/fabric-ca/commit/64c7d52) [FABC-874] Add HSM changes to Fabric CA docs (#47)
* [c45a0f6](https://github.com/hyperledger/fabric-ca/commit/c45a0f6) [FABC-865] Fix setting TLS files by cert/key.file (#42)
* [cc34360](https://github.com/hyperledger/fabric-ca/commit/cc34360) [FABC-880] Add license header to gencst_test.sh
* [63692a0](https://github.com/hyperledger/fabric-ca/commit/63692a0) Update to baseimage 0.4.16
* [5b1faaa](https://github.com/hyperledger/fabric-ca/commit/5b1faaa) Fix URL to contribution guide
* [3db5423](https://github.com/hyperledger/fabric-ca/commit/3db5423) [FABC-877] Reduce scope of tests with ssl off
* [eff05c9](https://github.com/hyperledger/fabric-ca/commit/eff05c9) [FABCI-420] Add sudo to apt-clean command
* [8a3698b](https://github.com/hyperledger/fabric-ca/commit/8a3698b) [FAB-16489](https://jira.hyperledger.org/browse/FAB-16489) Add CODEOWNERS
* [d84b685](https://github.com/hyperledger/fabric-ca/commit/d84b685) [FABCI-420] Add AZP yaml for release-1.4
* [040d68d](https://github.com/hyperledger/fabric-ca/commit/040d68d) [FABC-863] Test fail with open pipe in temp dir
* [b7fd4e8](https://github.com/hyperledger/fabric-ca/commit/b7fd4e8) FAB-16415 Prepare for next fabric-ca rel (1.4.4)

## v1.4.3
Mon Aug 26 15:40:49 EDT 2019

* [3e29f1a](https://github.com/hyperledger/fabric-ca/commit/3e29f1a) Remove hardcoded ver on multiarch script
* [c49e7d3](https://github.com/hyperledger/fabric-ca/commit/c49e7d3) [FABCI-401] Disable AnsiColor Wrapper
* [64bdb20](https://github.com/hyperledger/fabric-ca/commit/64bdb20) [FABC-867] Fix GoImports
* [017cea8](https://github.com/hyperledger/fabric-ca/commit/017cea8) FABC-862 Update mysql driver
* [c66adbe](https://github.com/hyperledger/fabric-ca/commit/c66adbe) [FAB-16000](https://jira.hyperledger.org/browse/FAB-16000) Prepare for next fabric-ca rel (1.4.3)

## v1.4.2
Wed Jul 17 14:55:08 EDT 2019

* [396c093](https://github.com/hyperledger/fabric-ca/commit/396c093) FABC-848 Fix TLS issue with PostgreSQL
* [f88e912](https://github.com/hyperledger/fabric-ca/commit/f88e912) [FABC-853] Adding metrics table LabelHelp support
* [5bf5d47](https://github.com/hyperledger/fabric-ca/commit/5bf5d47) [FABC-853] import fabric/gendoc for fabric-ca
* [477f5a2](https://github.com/hyperledger/fabric-ca/commit/477f5a2) FABC-837 Make metrics compatible with multi-root CA
* [4289522](https://github.com/hyperledger/fabric-ca/commit/4289522) Update fabric/bccsp and miekg/pkcs11 to latest revs
* [8b56ee8](https://github.com/hyperledger/fabric-ca/commit/8b56ee8) [FABC-850] Fix Fabric CA doc wrt OU types
* [f32e113](https://github.com/hyperledger/fabric-ca/commit/f32e113) FAB-15465: Update Jinja2
* [839c46e](https://github.com/hyperledger/fabric-ca/commit/839c46e) [FABC-842] Fabric CA Foc Fix
* [3004074](https://github.com/hyperledger/fabric-ca/commit/3004074) FABC-839 Update ca mutiarch publish script
* [3f449b5](https://github.com/hyperledger/fabric-ca/commit/3f449b5) [FAB-14969](https://jira.hyperledger.org/browse/FAB-14969) Prepare for next fabric-ca rel (1.4.2)

## v1.4.1
Thu Apr 11 11:08:16 EDT 2019

* [a32dd3c](https://github.com/hyperledger/fabric-ca/commit/a32dd3c) FABC-408 Add CORS support
* [7de4c77](https://github.com/hyperledger/fabric-ca/commit/7de4c77) FABC-833 Update Jenkinsfile
* [55f5eb7](https://github.com/hyperledger/fabric-ca/commit/55f5eb7) Fix --csr.hosts flag for client and server
* [19441cc](https://github.com/hyperledger/fabric-ca/commit/19441cc) FAB-14775 Update fabric-ca to baseimage 0.4.15
* [edb6e08](https://github.com/hyperledger/fabric-ca/commit/edb6e08) FABCI-311 Add ci pipeline script
* [aaee55f](https://github.com/hyperledger/fabric-ca/commit/aaee55f) [FABC-805] Wire DB metrics
* [197b881](https://github.com/hyperledger/fabric-ca/commit/197b881) [FABC-804] Create DB Metric Options
* [ea1ebbe](https://github.com/hyperledger/fabric-ca/commit/ea1ebbe) [FABC-803] Refactoring DB code
* [3c36ab5](https://github.com/hyperledger/fabric-ca/commit/3c36ab5) [FABC-795] Create a CA Server Health Check
* [8c245c1](https://github.com/hyperledger/fabric-ca/commit/8c245c1) [FABC-790] Create an operations server
* [8d9b622](https://github.com/hyperledger/fabric-ca/commit/8d9b622) [FABC-787] Wire in metrics for server APIs
* [08b1153](https://github.com/hyperledger/fabric-ca/commit/08b1153) [FABC-786] Vendor go-kit
* [81fa829](https://github.com/hyperledger/fabric-ca/commit/81fa829) [FABC-785] Add metrics for server APIs
* [ec59334](https://github.com/hyperledger/fabric-ca/commit/ec59334) [FABC-783] Add middleware to HTTP router
* [edb65ba](https://github.com/hyperledger/fabric-ca/commit/edb65ba) [FAB-14174](https://jira.hyperledger.org/browse/FAB-14174) Update GOVER to 1.11.5 in CA
* [3dafa32](https://github.com/hyperledger/fabric-ca/commit/3dafa32) Remove tcert from swagger
* [d3ef594](https://github.com/hyperledger/fabric-ca/commit/d3ef594) [FAB-13558](https://jira.hyperledger.org/browse/FAB-13558) Prepare fabric-ca for next rel (v1.4.1)

## v1.4.0
Tue Jan  8 12:21:52 EST 2019

* [cd6ed88](https://github.com/hyperledger/fabric-ca/commit/cd6ed88) FABC-781 Remove fabric-ca sample
* [b191f9c](https://github.com/hyperledger/fabric-ca/commit/b191f9c) [FAB-13393](https://jira.hyperledger.org/browse/FAB-13393) Prepare for next release (1.4.0)

## v1.4.0-rc2
Thu Dec 20 09:14:03 EST 2018

* [236dec5](https://github.com/hyperledger/fabric-ca/commit/236dec5) [FAB-13116](https://jira.hyperledger.org/browse/FAB-13116) Prepare for next rel (1.4.0 on release-1.4)

## v1.4.0-rc1
Mon Dec 10 15:08:08 EST 2018

* [4e4b1c2](https://github.com/hyperledger/fabric-ca/commit/4e4b1c2) FABC-771 Update multiarch script
* [e064dcc](https://github.com/hyperledger/fabric-ca/commit/e064dcc) [FABC-769] Add the ability to recover from panic
* [a0ebc50](https://github.com/hyperledger/fabric-ca/commit/a0ebc50) [FABC-765] Vendor fabric/bccsp/idemix
* [b2a3132](https://github.com/hyperledger/fabric-ca/commit/b2a3132) [FABC-768] Doc: Better Markup
* [8a8f1b3](https://github.com/hyperledger/fabric-ca/commit/8a8f1b3) [FABC-752] Vendor gomega and ginkgo
* [7b5f2b6](https://github.com/hyperledger/fabric-ca/commit/7b5f2b6) [FABC-767] Failing goimports
* [8c5bc35](https://github.com/hyperledger/fabric-ca/commit/8c5bc35) [FABC-757] add charset to mysql tables
* [2ebd68e](https://github.com/hyperledger/fabric-ca/commit/2ebd68e) [FABC-467] - Print TLS key used
* [d80509b](https://github.com/hyperledger/fabric-ca/commit/d80509b) [FABC-748]Incorrect version description of Go
* [99517e9](https://github.com/hyperledger/fabric-ca/commit/99517e9) [FAB-9938](https://jira.hyperledger.org/browse/FAB-9938) Add req method and uri to sig payload
* [b7a5590](https://github.com/hyperledger/fabric-ca/commit/b7a5590) [FABC-741] Update user doc for HSM configuration
* [b270271](https://github.com/hyperledger/fabric-ca/commit/b270271) [FABC-723] Brute force attack
* [a88ff53](https://github.com/hyperledger/fabric-ca/commit/a88ff53) [FAB-8475](https://jira.hyperledger.org/browse/FAB-8475) Run migration logic only if db level is old
* [ebbd2ed](https://github.com/hyperledger/fabric-ca/commit/ebbd2ed) [FAB-7347](https://jira.hyperledger.org/browse/FAB-7347) Flag and env var for logging level
* [bd7f997](https://github.com/hyperledger/fabric-ca/commit/bd7f997) [FABC-744] Revendor certificate-transparency-go
* [3c1585b](https://github.com/hyperledger/fabric-ca/commit/3c1585b) [FABC-459] Optimize GetCertificate request
* [bbe7b65](https://github.com/hyperledger/fabric-ca/commit/bbe7b65) [FAB-12444](https://jira.hyperledger.org/browse/FAB-12444) Update fabric-ca to baseimage 0.4.14
* [15209a3](https://github.com/hyperledger/fabric-ca/commit/15209a3) [FABC-740] Update to Go 1.11.1
* [cb7353f](https://github.com/hyperledger/fabric-ca/commit/cb7353f) [FABC-736] Use proper golint pkg
* [11cc823](https://github.com/hyperledger/fabric-ca/commit/11cc823) FABC-737 Fix goimports errors
* [959cd51](https://github.com/hyperledger/fabric-ca/commit/959cd51) [FABC-730] Update fabric-ca to baseimage 0.4.13
* [0de6679](https://github.com/hyperledger/fabric-ca/commit/0de6679) [FABC-492] Superfluous checks for deleting identity
* [16877b8](https://github.com/hyperledger/fabric-ca/commit/16877b8) [FAB-12141](https://jira.hyperledger.org/browse/FAB-12141) Prepare for next release (1.4.0 on master)
* [360f46e](https://github.com/hyperledger/fabric-ca/commit/360f46e) [FABC-703] Improved TLS error message

## v1.3.0-rc1
Mon Sep 24 19:30:06 EDT 2018

* [ab184f1](https://github.com/hyperledger/fabric-ca/commit/ab184f1) FABC-722 remove default hybrid image generation
* [2eda2f6](https://github.com/hyperledger/fabric-ca/commit/2eda2f6) FABC-563 Update Postgres version to 9.6 in s390x
* [8ecada3](https://github.com/hyperledger/fabric-ca/commit/8ecada3) FABC-720 update baseimage to 0.4.12
* [67dd000](https://github.com/hyperledger/fabric-ca/commit/67dd000) [FABC-718] NPE when listing all affiliations
* [d47dbf6](https://github.com/hyperledger/fabric-ca/commit/d47dbf6) [FAB-11992](https://jira.hyperledger.org/browse/FAB-11992) idemix role from boolean to int
* [6efd5e2](https://github.com/hyperledger/fabric-ca/commit/6efd5e2) FABC-719 Upgrade go version to 1.10.4
* [8d700d7](https://github.com/hyperledger/fabric-ca/commit/8d700d7) [FABC-716] Use current version for Base version
* [7cb4d81](https://github.com/hyperledger/fabric-ca/commit/7cb4d81) [FABC-709] Fix error message for LDAP converter
* [785ebd6](https://github.com/hyperledger/fabric-ca/commit/785ebd6) [FABC-711] Registration with LDAP throws better error
* [f32901e](https://github.com/hyperledger/fabric-ca/commit/f32901e) FABC-713 Update Baseimage to 0.4.11
* [b0e037c](https://github.com/hyperledger/fabric-ca/commit/b0e037c) [FABC-712] Updating fabric-amcl
* [b6196b1](https://github.com/hyperledger/fabric-ca/commit/b6196b1) [FABC-710] Omit duplicate if statement
* [2603374](https://github.com/hyperledger/fabric-ca/commit/2603374) [FABC-708] Revendor BCCSP
* [54f3bcf](https://github.com/hyperledger/fabric-ca/commit/54f3bcf) [FABC-706] Remove unused "fabric-ca" in gitignore
* [70b854e](https://github.com/hyperledger/fabric-ca/commit/70b854e) [FABC-704] Fix attribute name
* [1eb786b](https://github.com/hyperledger/fabric-ca/commit/1eb786b) [FAB-11200](https://jira.hyperledger.org/browse/FAB-11200) Create an errors package
* [ddc9c3d](https://github.com/hyperledger/fabric-ca/commit/ddc9c3d) [FAB-11232](https://jira.hyperledger.org/browse/FAB-11232) Fix removing expired nonces SQL
* [49d3936](https://github.com/hyperledger/fabric-ca/commit/49d3936) [FAB-10319](https://jira.hyperledger.org/browse/FAB-10319) Idemix FVT test with postgres & mysql
* [be1b7dc](https://github.com/hyperledger/fabric-ca/commit/be1b7dc) [FAB-8726](https://jira.hyperledger.org/browse/FAB-8726) Revoke one's own certificate
* [0a3e8f1](https://github.com/hyperledger/fabric-ca/commit/0a3e8f1) [FAB-8092](https://jira.hyperledger.org/browse/FAB-8092) Return 403 for authorization failures
* [e5bdbec](https://github.com/hyperledger/fabric-ca/commit/e5bdbec) [FAB-10498](https://jira.hyperledger.org/browse/FAB-10498) Fix Idemix SQL Query to Update Handle
* [901d150](https://github.com/hyperledger/fabric-ca/commit/901d150) [FAB-10386](https://jira.hyperledger.org/browse/FAB-10386) Revoked ID using Idemix should fail
* [4563457](https://github.com/hyperledger/fabric-ca/commit/4563457) [FAB-8868](https://jira.hyperledger.org/browse/FAB-8868) Fixed env var for key request
* [6b86289](https://github.com/hyperledger/fabric-ca/commit/6b86289) [FAB-10485](https://jira.hyperledger.org/browse/FAB-10485) Revendor Idemix Library
* [ae7a91a](https://github.com/hyperledger/fabric-ca/commit/ae7a91a) [FAB-8033](https://jira.hyperledger.org/browse/FAB-8033) Optimize DB queries
* [334f7f0](https://github.com/hyperledger/fabric-ca/commit/334f7f0) Prepare fabric-ca for 1.3.0 development
* [e44bf12](https://github.com/hyperledger/fabric-ca/commit/e44bf12) [FAB-10906](https://jira.hyperledger.org/browse/FAB-10906) Fix failing TestGetCertificatesDB
* [10b5711](https://github.com/hyperledger/fabric-ca/commit/10b5711) FAB-10821 make multiarch.sh executable
* [b00c1cb](https://github.com/hyperledger/fabric-ca/commit/b00c1cb) FAB-10753 prepare for next release
* [ab90eed](https://github.com/hyperledger/fabric-ca/commit/ab90eed) [FAB-10474](https://jira.hyperledger.org/browse/FAB-10474) Changed IsAdmin attr type to bool
* [4cd67f0](https://github.com/hyperledger/fabric-ca/commit/4cd67f0) [FAB-10671](https://jira.hyperledger.org/browse/FAB-10671) Re-enable idemix routes

## v1.2.0-rc1
Thu Jun 21 13:17:53 EDT 2018

* [5f0accc](https://github.com/hyperledger/fabric-ca/commit/5f0accc) FAB-10752 prepare for v1.2.0-rc1 release
* [8e852bc](https://github.com/hyperledger/fabric-ca/commit/8e852bc) [FAB-10737](https://jira.hyperledger.org/browse/FAB-10737) Fix release-all target
* [2697db3](https://github.com/hyperledger/fabric-ca/commit/2697db3) [FAB-10097](https://jira.hyperledger.org/browse/FAB-10097) Support for ecert flag in config.yaml
* [aaa51c1](https://github.com/hyperledger/fabric-ca/commit/aaa51c1) FAB-10294 add script to publish multiarch manifest
* [1f1fe2b](https://github.com/hyperledger/fabric-ca/commit/1f1fe2b) [FAB-10411](https://jira.hyperledger.org/browse/FAB-10411) Use default version when not set
* [260e1c3](https://github.com/hyperledger/fabric-ca/commit/260e1c3) [FAB-8548](https://jira.hyperledger.org/browse/FAB-8548) Fix CA started with wrong cert path
* [24bb938](https://github.com/hyperledger/fabric-ca/commit/24bb938) [FAB-8123](https://jira.hyperledger.org/browse/FAB-8123) Error out if --cacount is set for int CA
* [5e4106b](https://github.com/hyperledger/fabric-ca/commit/5e4106b) [FAB-10321](https://jira.hyperledger.org/browse/FAB-10321) Test Certificates API with MySQL
* [62259cc](https://github.com/hyperledger/fabric-ca/commit/62259cc) [FAB-10224](https://jira.hyperledger.org/browse/FAB-10224) Test Certificates API with PostgreSQL
* [7aa2298](https://github.com/hyperledger/fabric-ca/commit/7aa2298) [FAB-9938](https://jira.hyperledger.org/browse/FAB-9938) Add alert about not using TLS
* [1e28190](https://github.com/hyperledger/fabric-ca/commit/1e28190) [FAB-10494](https://jira.hyperledger.org/browse/FAB-10494) Fix formatting in user's guide
* [128b612](https://github.com/hyperledger/fabric-ca/commit/128b612) [FAB-10517](https://jira.hyperledger.org/browse/FAB-10517) Disabled idemix routes
* [5702371](https://github.com/hyperledger/fabric-ca/commit/5702371) [FAB-10419](https://jira.hyperledger.org/browse/FAB-10419) Incorrect filtering on affiliation
* [2e1fdf9](https://github.com/hyperledger/fabric-ca/commit/2e1fdf9) [FAB-10380](https://jira.hyperledger.org/browse/FAB-10380) Create keystore dir if does not exist
* [fb732d6](https://github.com/hyperledger/fabric-ca/commit/fb732d6) [FAB-10372](https://jira.hyperledger.org/browse/FAB-10372) Store revocation keys on the disk
* [adcf66b](https://github.com/hyperledger/fabric-ca/commit/adcf66b) FAB-10435 Update Makefile to support custom DOCKER_NS
* [9b49be6](https://github.com/hyperledger/fabric-ca/commit/9b49be6) [FAB-10341](https://jira.hyperledger.org/browse/FAB-10341) Identity load fails with only Idemix
* [db9ecd3](https://github.com/hyperledger/fabric-ca/commit/db9ecd3) FAB-10410 Update Dockerfiles to use DOCKER_NS
* [d16dab1](https://github.com/hyperledger/fabric-ca/commit/d16dab1) [FAB-10405](https://jira.hyperledger.org/browse/FAB-10405) Fix resp props for /cainfo in swagger doc
* [ac9e3cb](https://github.com/hyperledger/fabric-ca/commit/ac9e3cb) [FAB-10384](https://jira.hyperledger.org/browse/FAB-10384) Modify the document according to the code
* [37ba2c7](https://github.com/hyperledger/fabric-ca/commit/37ba2c7) [ FAB-6299 ] Remove getDNFromCert() method
* [a7a4075](https://github.com/hyperledger/fabric-ca/commit/a7a4075) [FAB-10324](https://jira.hyperledger.org/browse/FAB-10324) Add issuer revocation pub key to cainfo
* [69d5be1](https://github.com/hyperledger/fabric-ca/commit/69d5be1) [FAB-10101](https://jira.hyperledger.org/browse/FAB-10101) Verify token based on idemix cred
* [2032d77](https://github.com/hyperledger/fabric-ca/commit/2032d77) [FAB-7534](https://jira.hyperledger.org/browse/FAB-7534) Use strong ciphers for TLS
* [bedd37c](https://github.com/hyperledger/fabric-ca/commit/bedd37c) [FAB-10100](https://jira.hyperledger.org/browse/FAB-10100) Client changes for getting CRI
* [77dc5a6](https://github.com/hyperledger/fabric-ca/commit/77dc5a6) [FAB-9938](https://jira.hyperledger.org/browse/FAB-9938) Remove method and uri from token
* [59ffc4f](https://github.com/hyperledger/fabric-ca/commit/59ffc4f) [FAB-9999](https://jira.hyperledger.org/browse/FAB-9999) Update baseimage version
* [fc97373](https://github.com/hyperledger/fabric-ca/commit/fc97373) [FAB-10099](https://jira.hyperledger.org/browse/FAB-10099) Server changes for getting CRI
* [9091eb0](https://github.com/hyperledger/fabric-ca/commit/9091eb0) [FAB-10098](https://jira.hyperledger.org/browse/FAB-10098) API for getting CRI
* [f798e0d](https://github.com/hyperledger/fabric-ca/commit/f798e0d) [FAB-9244](https://jira.hyperledger.org/browse/FAB-9244) 7. Add CRI to the idemix enroll response
* [6a41a5a](https://github.com/hyperledger/fabric-ca/commit/6a41a5a) [FAB-9244](https://jira.hyperledger.org/browse/FAB-9244) 6. Revendored idemix package
* [c44f5e1](https://github.com/hyperledger/fabric-ca/commit/c44f5e1) [FAB-9244](https://jira.hyperledger.org/browse/FAB-9244) 5.Client changes to get Idemix credential
* [84653b2](https://github.com/hyperledger/fabric-ca/commit/84653b2) [FAB-9244](https://jira.hyperledger.org/browse/FAB-9244) 4. Refactor issuer code to issuer.go
* [33900e7](https://github.com/hyperledger/fabric-ca/commit/33900e7) [FAB-9244](https://jira.hyperledger.org/browse/FAB-9244) 3.Changes for nonce management
* [1d632b8](https://github.com/hyperledger/fabric-ca/commit/1d632b8) [FAB-9244](https://jira.hyperledger.org/browse/FAB-9244) 2.Server changes to get Idemix credential
* [a9644b4](https://github.com/hyperledger/fabric-ca/commit/a9644b4) [FAB-10043](https://jira.hyperledger.org/browse/FAB-10043) 5. Add flag to store certificates
* [e1d4490](https://github.com/hyperledger/fabric-ca/commit/e1d4490) [FAB-9887](https://jira.hyperledger.org/browse/FAB-9887) Generate docs for client commands
* [b053b4f](https://github.com/hyperledger/fabric-ca/commit/b053b4f) [FAB-7238](https://jira.hyperledger.org/browse/FAB-7238) 4. DB query to get certificates
* [02858a7](https://github.com/hyperledger/fabric-ca/commit/02858a7) [FAB-9938](https://jira.hyperledger.org/browse/FAB-9938) Add req method and uri to sig payload
* [53322cf](https://github.com/hyperledger/fabric-ca/commit/53322cf) [FAB-9958](https://jira.hyperledger.org/browse/FAB-9958) Handle colons in revoke command input
* [f616de8](https://github.com/hyperledger/fabric-ca/commit/f616de8) [FAB-7238](https://jira.hyperledger.org/browse/FAB-7238) Vendor certificate printing package
* [f3bd5b9](https://github.com/hyperledger/fabric-ca/commit/f3bd5b9)  [FAB-9244](https://jira.hyperledger.org/browse/FAB-9244) 1. API for getting idemix credential
* [f718bb5](https://github.com/hyperledger/fabric-ca/commit/f718bb5) [FAB-9243](https://jira.hyperledger.org/browse/FAB-9243) Add ability to get CA's idemix public key
* [bd52dc4](https://github.com/hyperledger/fabric-ca/commit/bd52dc4) [FAB-9957](https://jira.hyperledger.org/browse/FAB-9957) Skip license check for generated files
* [2b5ed40](https://github.com/hyperledger/fabric-ca/commit/2b5ed40) [FAB-7882](https://jira.hyperledger.org/browse/FAB-7882) Need wildcard for bootstrap user
* [45653f2](https://github.com/hyperledger/fabric-ca/commit/45653f2) [FAB-7238](https://jira.hyperledger.org/browse/FAB-7238) 3. CLI Input Validation, Time Parsing, Auth
* [ba1fb5b](https://github.com/hyperledger/fabric-ca/commit/ba1fb5b) FAB-9861 fix broken links
* [9869b94](https://github.com/hyperledger/fabric-ca/commit/9869b94) [FAB-7238](https://jira.hyperledger.org/browse/FAB-7238) 2. CLI for listing certificates
* [34d5148](https://github.com/hyperledger/fabric-ca/commit/34d5148) [FAB-9243](https://jira.hyperledger.org/browse/FAB-9243) Vendored idemix and amcl packages
* [25e9d11](https://github.com/hyperledger/fabric-ca/commit/25e9d11) [FAB-7238](https://jira.hyperledger.org/browse/FAB-7238) 1. Define the API for listing certs
* [403f2f7](https://github.com/hyperledger/fabric-ca/commit/403f2f7) [FAB-9392](https://jira.hyperledger.org/browse/FAB-9392) Refactor client CLI code
* [3d9dbb7](https://github.com/hyperledger/fabric-ca/commit/3d9dbb7) [FAB-1446](https://jira.hyperledger.org/browse/FAB-1446) Adding the run_safesql_scan script
* [6b16ad8](https://github.com/hyperledger/fabric-ca/commit/6b16ad8) [FAB-9258](https://jira.hyperledger.org/browse/FAB-9258) Create interface to help with unit-tests
* [e2f93e0](https://github.com/hyperledger/fabric-ca/commit/e2f93e0) [FAB-6299](https://jira.hyperledger.org/browse/FAB-6299) Update certificate-transparency-go pkg
* [3754d15](https://github.com/hyperledger/fabric-ca/commit/3754d15) FAB-9352 add CODE_OF_CONDUCT.md
* [e83ff5b](https://github.com/hyperledger/fabric-ca/commit/e83ff5b) FAB-9078 Update go version to 1.10
* [2fa2174](https://github.com/hyperledger/fabric-ca/commit/2fa2174) FAB-9194 Add tox.ini for building docs in CI
* [ebc9fef](https://github.com/hyperledger/fabric-ca/commit/ebc9fef) [FAB-9080](https://jira.hyperledger.org/browse/FAB-9080) Prepare fabric-ca for 1.2 development
* [3601d59](https://github.com/hyperledger/fabric-ca/commit/3601d59) [FAB-8859](https://jira.hyperledger.org/browse/FAB-8859) Include checks for empty certificate
* [68c210b](https://github.com/hyperledger/fabric-ca/commit/68c210b) [FAB-8750](https://jira.hyperledger.org/browse/FAB-8750) Fabric-ca docs need updating

## v1.1.0-rc1
Thu Mar  1 13:05:50 EST 2018

* [15156fd](https://github.com/hyperledger/fabric-ca/commit/15156fd) [ FAB-8417 ] Update cluster doc for migration
* [68889bf](https://github.com/hyperledger/fabric-ca/commit/68889bf) [FAB-8494](https://jira.hyperledger.org/browse/FAB-8494) doc case sensitiveness of affiliations
* [5665f2a](https://github.com/hyperledger/fabric-ca/commit/5665f2a) [FAB-8565](https://jira.hyperledger.org/browse/FAB-8565) Fix duplicate description in usersguide
* [3ce971f](https://github.com/hyperledger/fabric-ca/commit/3ce971f) [FAB-8547](https://jira.hyperledger.org/browse/FAB-8547) Fix ca.keyfile args typo in documents
* [680960e](https://github.com/hyperledger/fabric-ca/commit/680960e) FAB-8485 update go version to 1.9.2
* [2308eab](https://github.com/hyperledger/fabric-ca/commit/2308eab) [FAB-8451](https://jira.hyperledger.org/browse/FAB-8451) Fix certificate close to expire
* [6f05f0e](https://github.com/hyperledger/fabric-ca/commit/6f05f0e) [FAB-6673](https://jira.hyperledger.org/browse/FAB-6673) Added release and dist targets
* [d5e6ea7](https://github.com/hyperledger/fabric-ca/commit/d5e6ea7) [FAB-6673](https://jira.hyperledger.org/browse/FAB-6673) Updated certificate-transparency-go pkg
* [3a99450](https://github.com/hyperledger/fabric-ca/commit/3a99450) [FAB-8448](https://jira.hyperledger.org/browse/FAB-8448) Update fabric-ca's pkcs11 package
* [be71804](https://github.com/hyperledger/fabric-ca/commit/be71804) FAB-8365 update baseimage version to 0.4.6
* [bd695ae](https://github.com/hyperledger/fabric-ca/commit/bd695ae) [FAB-8029](https://jira.hyperledger.org/browse/FAB-8029) Fix some log messages
* [1c5f433](https://github.com/hyperledger/fabric-ca/commit/1c5f433) [FAB-7993](https://jira.hyperledger.org/browse/FAB-7993) Document attribute behavior
* [bc4c06f](https://github.com/hyperledger/fabric-ca/commit/bc4c06f) [FAB-7967](https://jira.hyperledger.org/browse/FAB-7967) Add id column to affiliations table
* [0fb839d](https://github.com/hyperledger/fabric-ca/commit/0fb839d) [FAB-7894](https://jira.hyperledger.org/browse/FAB-7894) Use recursive references
* [f27a31d](https://github.com/hyperledger/fabric-ca/commit/f27a31d) [FAB-7921](https://jira.hyperledger.org/browse/FAB-7921) Don't use defaults for modify identity
* [9a45730](https://github.com/hyperledger/fabric-ca/commit/9a45730) [FAB-7990](https://jira.hyperledger.org/browse/FAB-7990) Fix debug flag
* [3ee02e0](https://github.com/hyperledger/fabric-ca/commit/3ee02e0) [FAB-7970](https://jira.hyperledger.org/browse/FAB-7970) Fix max enrollment default value
* [4dba361](https://github.com/hyperledger/fabric-ca/commit/4dba361) [ FAB-8116 ] Fix bad merge causing CI failure
* [b9d3e01](https://github.com/hyperledger/fabric-ca/commit/b9d3e01) [ FAB-5726 ] Test dyn add/mod/del identites
* [f66397d](https://github.com/hyperledger/fabric-ca/commit/f66397d) [ FAB-6511 ] Dynamic modify of affiliations
* [911d901](https://github.com/hyperledger/fabric-ca/commit/911d901) [FAB-7893](https://jira.hyperledger.org/browse/FAB-7893) Prevent unforced delete of sub-affiliations
* [b1ed44e](https://github.com/hyperledger/fabric-ca/commit/b1ed44e) [ FAB-3416 ] Enhance fvt image LDAP attributes
* [71974f5](https://github.com/hyperledger/fabric-ca/commit/71974f5) FAB-7786 prepare fabric-ca for next release

## v1.1.0-alpha
Fri Jan 26 14:48:54 EST 2018

* [94604d5](https://github.com/hyperledger/fabric-ca/commit/94604d5) FAB-7783 prepare fabric-ca for v1.1.0-alpha
* [e33ebdf](https://github.com/hyperledger/fabric-ca/commit/e33ebdf) [FAB-7932](https://jira.hyperledger.org/browse/FAB-7932) Version test failure for release
* [437d27e](https://github.com/hyperledger/fabric-ca/commit/437d27e) FAB-7924 update fabric-baseimage version
* [ca705f6](https://github.com/hyperledger/fabric-ca/commit/ca705f6) [FAB-7812](https://jira.hyperledger.org/browse/FAB-7812) Fix the APIs to return info correctly
* [5594cca](https://github.com/hyperledger/fabric-ca/commit/5594cca) [ FAB-7865 ] Remove trailing blanks from files
* [d31916c](https://github.com/hyperledger/fabric-ca/commit/d31916c) [FAB-7660](https://jira.hyperledger.org/browse/FAB-7660) Fix LDAP missing attribute error
* [ad88250](https://github.com/hyperledger/fabric-ca/commit/ad88250) [FAB-7620](https://jira.hyperledger.org/browse/FAB-7620) Return err when revoking revoked cert
* [135b81c](https://github.com/hyperledger/fabric-ca/commit/135b81c) [ FAB-7207 ] Test CRL as part of revoke
* [e39b3e4](https://github.com/hyperledger/fabric-ca/commit/e39b3e4) [FAB-7464](https://jira.hyperledger.org/browse/FAB-7464) Don't use RevokedBefore if not set
* [ea386ca](https://github.com/hyperledger/fabric-ca/commit/ea386ca) [FAB-7465](https://jira.hyperledger.org/browse/FAB-7465) Fix the authority checks on attributes
* [2c88247](https://github.com/hyperledger/fabric-ca/commit/2c88247) [FAB-7619](https://jira.hyperledger.org/browse/FAB-7619) Fix case handling in LDAP converter
* [1209e25](https://github.com/hyperledger/fabric-ca/commit/1209e25) [FAB-7662](https://jira.hyperledger.org/browse/FAB-7662) Add SQLite support for migration
* [52e5d66](https://github.com/hyperledger/fabric-ca/commit/52e5d66) [FAB-7646](https://jira.hyperledger.org/browse/FAB-7646) certs should expire before issuing cert
* [ebfc050](https://github.com/hyperledger/fabric-ca/commit/ebfc050) [FAB-7471](https://jira.hyperledger.org/browse/FAB-7471) Add missing libs to docker images
* [c219a5e](https://github.com/hyperledger/fabric-ca/commit/c219a5e) [FAB-7596](https://jira.hyperledger.org/browse/FAB-7596) Modify enroll cmd to read env var
* [48defd8](https://github.com/hyperledger/fabric-ca/commit/48defd8) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 9. Dynamic Cfg - Aff: Modify
* [66fafe2](https://github.com/hyperledger/fabric-ca/commit/66fafe2) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 8. Dynamic Cfg - Aff: Add/Remove
* [e50822a](https://github.com/hyperledger/fabric-ca/commit/e50822a) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 7. Dynamic Cfg - Aff: Get
* [bc33398](https://github.com/hyperledger/fabric-ca/commit/bc33398) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 6. Dynamic Cfg - Aff: CLI
* [332d940](https://github.com/hyperledger/fabric-ca/commit/332d940) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 5. Dynamic Cfg - identities: Modify
* [68c8eec](https://github.com/hyperledger/fabric-ca/commit/68c8eec) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 4. Dynamic Cfg - identities: Add/Remove
* [ba15457](https://github.com/hyperledger/fabric-ca/commit/ba15457) [FAB-6328](https://jira.hyperledger.org/browse/FAB-6328) Fix cleanup of unit-tests temp files
* [195992b](https://github.com/hyperledger/fabric-ca/commit/195992b) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 3. Dynamic Cfg - identities: GetIDs
* [d0fd310](https://github.com/hyperledger/fabric-ca/commit/d0fd310) [FAB-7348](https://jira.hyperledger.org/browse/FAB-7348) Set user max enrollments correctly
* [6ae8f06](https://github.com/hyperledger/fabric-ca/commit/6ae8f06) [FAB-7524](https://jira.hyperledger.org/browse/FAB-7524) Improve error checking for key lookup
* [7b4ada4](https://github.com/hyperledger/fabric-ca/commit/7b4ada4) [FAB-3416](https://jira.hyperledger.org/browse/FAB-3416) Map LDAP attrs to fabric CA attrs
* [98da125](https://github.com/hyperledger/fabric-ca/commit/98da125) [FAB-7458](https://jira.hyperledger.org/browse/FAB-7458) JSON streamer
* [6c06895](https://github.com/hyperledger/fabric-ca/commit/6c06895) [FAB-6932](https://jira.hyperledger.org/browse/FAB-6932) Unstage key variation test
* [1443a7d](https://github.com/hyperledger/fabric-ca/commit/1443a7d) [FAB-3416](https://jira.hyperledger.org/browse/FAB-3416) Vendoring govaluate
* [a82b326](https://github.com/hyperledger/fabric-ca/commit/a82b326) [FAB-3159](https://jira.hyperledger.org/browse/FAB-3159) Update vendored version of viper
* [bacb382](https://github.com/hyperledger/fabric-ca/commit/bacb382) [FAB-7489](https://jira.hyperledger.org/browse/FAB-7489) TLS test certs are expired
* [52ea881](https://github.com/hyperledger/fabric-ca/commit/52ea881) [FAB-7223](https://jira.hyperledger.org/browse/FAB-7223) Wrap CRL PEM file at 64 characters
* [b57c216](https://github.com/hyperledger/fabric-ca/commit/b57c216) [ FAB-7448 ] check_format trailing blanks
* [be05c87](https://github.com/hyperledger/fabric-ca/commit/be05c87) [ FAB-6452 ] fabric-ca CSR to external CA
* [6443f43](https://github.com/hyperledger/fabric-ca/commit/6443f43) [ FAB-6448 ] Version command test
* [25c2411](https://github.com/hyperledger/fabric-ca/commit/25c2411) [FAB-4828](https://jira.hyperledger.org/browse/FAB-4828) Make docker namespace configurable
* [f5af79b](https://github.com/hyperledger/fabric-ca/commit/f5af79b) [FAB-6932](https://jira.hyperledger.org/browse/FAB-6932) Unmarshal key request object correctly
* [7f12e2c](https://github.com/hyperledger/fabric-ca/commit/7f12e2c) [FAB-7344](https://jira.hyperledger.org/browse/FAB-7344) Set default TLS cert file name
* [1c6ef12](https://github.com/hyperledger/fabric-ca/commit/1c6ef12) [FAB-7291](https://jira.hyperledger.org/browse/FAB-7291) Set default value for Chainfile attribute
* [604a634](https://github.com/hyperledger/fabric-ca/commit/604a634) [FAB-7235](https://jira.hyperledger.org/browse/FAB-7235) Check profile for isCA
* [f187f3d](https://github.com/hyperledger/fabric-ca/commit/f187f3d) [FAB-6647](https://jira.hyperledger.org/browse/FAB-6647) 2. Maintain backwards compatibility
* [6b6b294](https://github.com/hyperledger/fabric-ca/commit/6b6b294) [FAB-6647](https://jira.hyperledger.org/browse/FAB-6647) 1. Maintain backwards compatibility
* [7a17a94](https://github.com/hyperledger/fabric-ca/commit/7a17a94) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 2. Dynamic Cfg - identities: CLI2
* [3fad051](https://github.com/hyperledger/fabric-ca/commit/3fad051) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) 1. Dynamic Cfg - Identities: CLI
* [b924bcb](https://github.com/hyperledger/fabric-ca/commit/b924bcb) [FAB-6817](https://jira.hyperledger.org/browse/FAB-6817) Check if CA cert has 'crl sign' usage
* [77c6498](https://github.com/hyperledger/fabric-ca/commit/77c6498) [FAB-6405](https://jira.hyperledger.org/browse/FAB-6405) Fix cert/key paths with --cacount
* [e554d99](https://github.com/hyperledger/fabric-ca/commit/e554d99) [FAB-7008](https://jira.hyperledger.org/browse/FAB-7008) Fix compilation error
* [cd74c8a](https://github.com/hyperledger/fabric-ca/commit/cd74c8a) [FAB-6991](https://jira.hyperledger.org/browse/FAB-6991) Fix max enrollments for bootstrap user
* [eee7cb7](https://github.com/hyperledger/fabric-ca/commit/eee7cb7) [FAB-6993](https://jira.hyperledger.org/browse/FAB-6993) Add troubleshooting tip
* [b3c00ea](https://github.com/hyperledger/fabric-ca/commit/b3c00ea) [FAB-6321](https://jira.hyperledger.org/browse/FAB-6321) Store CA certs in child-first order
* [0587ca8](https://github.com/hyperledger/fabric-ca/commit/0587ca8) [FAB-6871](https://jira.hyperledger.org/browse/FAB-6871) Set OUs in ECerts
* [69d2d18](https://github.com/hyperledger/fabric-ca/commit/69d2d18) [ FAB-6963 ] Fix binary data in log file
* [15c7635](https://github.com/hyperledger/fabric-ca/commit/15c7635) [FAB-6710](https://jira.hyperledger.org/browse/FAB-6710) Remove GetUserInfo call
* [eb3eac0](https://github.com/hyperledger/fabric-ca/commit/eb3eac0) [ FAB-6976 ] Default timeout for cluster test
* [ae842d0](https://github.com/hyperledger/fabric-ca/commit/ae842d0) [FAB-6964](https://jira.hyperledger.org/browse/FAB-6964) fix load-tester compilation issue
* [3175ee7](https://github.com/hyperledger/fabric-ca/commit/3175ee7) [FAB-5462](https://jira.hyperledger.org/browse/FAB-5462) Remove non-existent files from yaml
* [d353303](https://github.com/hyperledger/fabric-ca/commit/d353303) [FAB-6946](https://jira.hyperledger.org/browse/FAB-6946) Add target for fabric-ca image alone
* [b5285b5](https://github.com/hyperledger/fabric-ca/commit/b5285b5) [FAB-6930](https://jira.hyperledger.org/browse/FAB-6930) Permit lists with brackets
* [ab7a40b](https://github.com/hyperledger/fabric-ca/commit/ab7a40b) [ FAB-6698 ] Fabric CA clustering
* [6eb74e1](https://github.com/hyperledger/fabric-ca/commit/6eb74e1) [FAB-6917](https://jira.hyperledger.org/browse/FAB-6917) Vendor gorilla/mux
* [b5373f6](https://github.com/hyperledger/fabric-ca/commit/b5373f6) [ FAB-6864 ] Increase default start timeout
* [626f943](https://github.com/hyperledger/fabric-ca/commit/626f943) [FAB-6842](https://jira.hyperledger.org/browse/FAB-6842) Change rc for some endpoints to 201
* [059753e](https://github.com/hyperledger/fabric-ca/commit/059753e) [FAB-6899](https://jira.hyperledger.org/browse/FAB-6899) Fix affiliation in swagger doc
* [a9d6569](https://github.com/hyperledger/fabric-ca/commit/a9d6569) [FAB-6745](https://jira.hyperledger.org/browse/FAB-6745) Add netcat to fabric-ca images
* [dca4740](https://github.com/hyperledger/fabric-ca/commit/dca4740) Fix [FAB-6768](https://jira.hyperledger.org/browse/FAB-6768)
* [d98663f](https://github.com/hyperledger/fabric-ca/commit/d98663f) [FAB-5726](https://jira.hyperledger.org/browse/FAB-5726) Update swagger for dynamic update
* [2431f12](https://github.com/hyperledger/fabric-ca/commit/2431f12) FAB-6826 Prepare fabric-ca for next release
* [33f3629](https://github.com/hyperledger/fabric-ca/commit/33f3629) [FAB-6475](https://jira.hyperledger.org/browse/FAB-6475) Add well-known attributes to identities
* [60fbd62](https://github.com/hyperledger/fabric-ca/commit/60fbd62) [FAB-5300](https://jira.hyperledger.org/browse/FAB-5300) Added gencrl option to the revoke cmd

## v1.1.0-preview
Wed Nov  1 10:12:26 EDT 2017

* [92f2cf6](https://github.com/hyperledger/fabric-ca/commit/92f2cf6) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) - ABAC doc
* [37cbb14](https://github.com/hyperledger/fabric-ca/commit/37cbb14) [FAB-6675](https://jira.hyperledger.org/browse/FAB-6675) Document sqlite db locked error
* [5c9086f](https://github.com/hyperledger/fabric-ca/commit/5c9086f) [FAB-5782](https://jira.hyperledger.org/browse/FAB-5782) Initialization failure on Postgres
* [5d2f1b5](https://github.com/hyperledger/fabric-ca/commit/5d2f1b5) [FAB-6508](https://jira.hyperledger.org/browse/FAB-6508) Unique db names for cacount option
* [9a87e6d](https://github.com/hyperledger/fabric-ca/commit/9a87e6d) [FAB-6661](https://jira.hyperledger.org/browse/FAB-6661) Update version to 1.1.0
* [4edfdd8](https://github.com/hyperledger/fabric-ca/commit/4edfdd8) [FAB-6672](https://jira.hyperledger.org/browse/FAB-6672) Moved fvt script to right directory
* [7b42a83](https://github.com/hyperledger/fabric-ca/commit/7b42a83) [FAB-6662](https://jira.hyperledger.org/browse/FAB-6662) Make enroll attrs required by default
* [50b828b](https://github.com/hyperledger/fabric-ca/commit/50b828b) [FAB-6643](https://jira.hyperledger.org/browse/FAB-6643) Add ci.properties file
* [fddda65](https://github.com/hyperledger/fabric-ca/commit/fddda65) Update URL for MAINTAINERS source
* [b74248d](https://github.com/hyperledger/fabric-ca/commit/b74248d) [FAB-6575](https://jira.hyperledger.org/browse/FAB-6575) Fix missing attr from bootstrap user
* [aa10999](https://github.com/hyperledger/fabric-ca/commit/aa10999) [FAB-6035](https://jira.hyperledger.org/browse/FAB-6035) Validate attributes being registered
* [3e15d7e](https://github.com/hyperledger/fabric-ca/commit/3e15d7e) [FAB-6529](https://jira.hyperledger.org/browse/FAB-6529) Fix new CA unit-tests
* [2528217](https://github.com/hyperledger/fabric-ca/commit/2528217) [FAB-6561](https://jira.hyperledger.org/browse/FAB-6561) Close DB when initCA fails
* [5172de7](https://github.com/hyperledger/fabric-ca/commit/5172de7) [FAB-6562](https://jira.hyperledger.org/browse/FAB-6562) Rename NewCA to make it private
* [0a42217](https://github.com/hyperledger/fabric-ca/commit/0a42217) [FAB-6247](https://jira.hyperledger.org/browse/FAB-6247) Sanitize debug messages
* [7256a44](https://github.com/hyperledger/fabric-ca/commit/7256a44) [FAB-5300](https://jira.hyperledger.org/browse/FAB-5300) Fix test cases failing on Mac
* [c553bc0](https://github.com/hyperledger/fabric-ca/commit/c553bc0) [FAB-6332](https://jira.hyperledger.org/browse/FAB-6332) Save msp dir in default client config file
* [086e651](https://github.com/hyperledger/fabric-ca/commit/086e651) [FAB-5300](https://jira.hyperledger.org/browse/FAB-5300) Updated github.com/stretchr/testify pkg
* [dc9ab3d](https://github.com/hyperledger/fabric-ca/commit/dc9ab3d) [ FAB-6516 ] certification path validation go1.9
* [76fb6ec](https://github.com/hyperledger/fabric-ca/commit/76fb6ec) [FAB-5300](https://jira.hyperledger.org/browse/FAB-5300) Add support to generate CRL
* [813fafa](https://github.com/hyperledger/fabric-ca/commit/813fafa) [FAB-6445](https://jira.hyperledger.org/browse/FAB-6445) Add missing "ecert" field to swagger
* [a030aae](https://github.com/hyperledger/fabric-ca/commit/a030aae) [FAB-6374](https://jira.hyperledger.org/browse/FAB-6374) Update release notes
* [339d5b1](https://github.com/hyperledger/fabric-ca/commit/339d5b1) [ FAB-6337 ] Update BASEREL version in Makefile
* [09f4bda](https://github.com/hyperledger/fabric-ca/commit/09f4bda) [ FAB-6339 ] Update fabric-ca_setup.sh polling
* [0ed7e38](https://github.com/hyperledger/fabric-ca/commit/0ed7e38) [FAB-6360](https://jira.hyperledger.org/browse/FAB-6360) Update license text in README
* [618353f](https://github.com/hyperledger/fabric-ca/commit/618353f) [ FAB-2919 ] Set postgres SSL environment
* [21ee6a1](https://github.com/hyperledger/fabric-ca/commit/21ee6a1) [ FAB-6320 ] Trim logs for CI builds
* [2780ccb](https://github.com/hyperledger/fabric-ca/commit/2780ccb) [FAB-5426](https://jira.hyperledger.org/browse/FAB-5426) Fix unit-tests on vagrant/windows
* [8fa1ed8](https://github.com/hyperledger/fabric-ca/commit/8fa1ed8) [FAB-6302](https://jira.hyperledger.org/browse/FAB-6302) Add json tag to AttrReqs field
* [57c0cf3](https://github.com/hyperledger/fabric-ca/commit/57c0cf3) [FAB-5060](https://jira.hyperledger.org/browse/FAB-5060) Update DB schema
* [c65b634](https://github.com/hyperledger/fabric-ca/commit/c65b634) [FAB-6050](https://jira.hyperledger.org/browse/FAB-6050) Added jq to fabric-ca-tools container
* [b21aa3b](https://github.com/hyperledger/fabric-ca/commit/b21aa3b) [FAB-6050](https://jira.hyperledger.org/browse/FAB-6050) Add fabric images with fabric-ca-client
* [bb5691b](https://github.com/hyperledger/fabric-ca/commit/bb5691b) [FAB-6278](https://jira.hyperledger.org/browse/FAB-6278) Adding another troubleshooting tip
* [d6f2461](https://github.com/hyperledger/fabric-ca/commit/d6f2461) [FAB-5300](https://jira.hyperledger.org/browse/FAB-5300) Updated cfssl to add crl package
* [43a3bef](https://github.com/hyperledger/fabric-ca/commit/43a3bef) [FAB-6181](https://jira.hyperledger.org/browse/FAB-6181) Add HSM section to the Fabric CA users guide
* [ba55903](https://github.com/hyperledger/fabric-ca/commit/ba55903) [ FAB-5773 ] Increase ca.go test coverage
* [307d7d8](https://github.com/hyperledger/fabric-ca/commit/307d7d8) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) Doc update for attributes in ECerts
* [58e337b](https://github.com/hyperledger/fabric-ca/commit/58e337b) [FAB-6247](https://jira.hyperledger.org/browse/FAB-6247) Sanitize debug messages
* [1cfe8b3](https://github.com/hyperledger/fabric-ca/commit/1cfe8b3) [FAB-6248](https://jira.hyperledger.org/browse/FAB-6248) Make docs part of CI
* [f7cc93a](https://github.com/hyperledger/fabric-ca/commit/f7cc93a) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) Use vendored attrmgr
* [3b9d83c](https://github.com/hyperledger/fabric-ca/commit/3b9d83c) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) Vendoring attrmgr from fabric
* [f3028c4](https://github.com/hyperledger/fabric-ca/commit/f3028c4) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) Attribute-based access control (#4)
* [d7b554c](https://github.com/hyperledger/fabric-ca/commit/d7b554c) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) Attribute-based access control (#3)
* [27b9697](https://github.com/hyperledger/fabric-ca/commit/27b9697) FAB-5925 Compile fabric-ca with Go 1.9
* [efc7232](https://github.com/hyperledger/fabric-ca/commit/efc7232) [FAB-6168](https://jira.hyperledger.org/browse/FAB-6168) Store TLS signing certs in proper dir
* [55afb3d](https://github.com/hyperledger/fabric-ca/commit/55afb3d) [FAB-6085](https://jira.hyperledger.org/browse/FAB-6085) Fixes server CA DBs management
* [2dd4f5b](https://github.com/hyperledger/fabric-ca/commit/2dd4f5b) [FAB-6068](https://jira.hyperledger.org/browse/FAB-6068) Update state after all checks done
* [c41f4f1](https://github.com/hyperledger/fabric-ca/commit/c41f4f1) [FAB-6187](https://jira.hyperledger.org/browse/FAB-6187) Start troubleshooting for fabric-ca
* [b2fb753](https://github.com/hyperledger/fabric-ca/commit/b2fb753) [FAB-5786](https://jira.hyperledger.org/browse/FAB-5786) DB initialization made more resilient
* [02c8f4e](https://github.com/hyperledger/fabric-ca/commit/02c8f4e) [FAB-5935](https://jira.hyperledger.org/browse/FAB-5935) Fixes TestSRVServerInit and more on vagrant
* [57aa82c](https://github.com/hyperledger/fabric-ca/commit/57aa82c) [FAB-2840](https://jira.hyperledger.org/browse/FAB-2840) Add home directory configuration
* [11ca4d3](https://github.com/hyperledger/fabric-ca/commit/11ca4d3) [FAB-5740](https://jira.hyperledger.org/browse/FAB-5740) Remove TCerts from documentation
* [2339c6c](https://github.com/hyperledger/fabric-ca/commit/2339c6c) [FAB-5427](https://jira.hyperledger.org/browse/FAB-5427) Fixes TestNewUserRegistryMySQL on vagrant
* [53bd27f](https://github.com/hyperledger/fabric-ca/commit/53bd27f) [FAB-5679](https://jira.hyperledger.org/browse/FAB-5679) Allow empty affiliation string
* [5a01179](https://github.com/hyperledger/fabric-ca/commit/5a01179) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) Attribute-based access control (#2)
* [487c413](https://github.com/hyperledger/fabric-ca/commit/487c413) [FAB-5346](https://jira.hyperledger.org/browse/FAB-5346) Attribute-based access control (#1)
* [d332960](https://github.com/hyperledger/fabric-ca/commit/d332960) [FAB-4462](https://jira.hyperledger.org/browse/FAB-4462) Scripts to dynamically generate readme
* [446f9cf](https://github.com/hyperledger/fabric-ca/commit/446f9cf) [FAB-5697](https://jira.hyperledger.org/browse/FAB-5697) Make identity type optional to register
* [cb71418](https://github.com/hyperledger/fabric-ca/commit/cb71418) [FAB-3013](https://jira.hyperledger.org/browse/FAB-3013) Benchmarks for server request handlers
* [7bca42a](https://github.com/hyperledger/fabric-ca/commit/7bca42a) [FAB-3013](https://jira.hyperledger.org/browse/FAB-3013) Run servers at 0.0.0.0 in the FVT image
* [85cd788](https://github.com/hyperledger/fabric-ca/commit/85cd788) [ FAB-5555 ] Improve password-masking test
* [3c819af](https://github.com/hyperledger/fabric-ca/commit/3c819af) [ FAB-5521 ] Fix CI build fail x86 for slapd
* [3d521fc](https://github.com/hyperledger/fabric-ca/commit/3d521fc) [ FAB-1383 ] Add TLS tests for mysql
* [c678910](https://github.com/hyperledger/fabric-ca/commit/c678910) [ FAB-3982 ] TLS dynamic certs for fabric-ca tests
* [940cc6a](https://github.com/hyperledger/fabric-ca/commit/940cc6a) [FAB-3013](https://jira.hyperledger.org/browse/FAB-3013) Reuse connections in the client
* [e3a10f2](https://github.com/hyperledger/fabric-ca/commit/e3a10f2) [FAB-3013](https://jira.hyperledger.org/browse/FAB-3013) Simple load test driver for Fabric CA server
* [a0af417](https://github.com/hyperledger/fabric-ca/commit/a0af417) [FAB-5707](https://jira.hyperledger.org/browse/FAB-5707) Integrate pkg/errors with httpErr
* [f59c655](https://github.com/hyperledger/fabric-ca/commit/f59c655) [FAB-5707](https://jira.hyperledger.org/browse/FAB-5707) Use pkg/errors to create errors
* [f8a910f](https://github.com/hyperledger/fabric-ca/commit/f8a910f) [FAB-5058](https://jira.hyperledger.org/browse/FAB-5058) Auto generate TLS certificates
* [17e530d](https://github.com/hyperledger/fabric-ca/commit/17e530d) [FAB-3458](https://jira.hyperledger.org/browse/FAB-3458) Use viper instance in server/client cmds
* [f77203e](https://github.com/hyperledger/fabric-ca/commit/f77203e) [FAB-3458](https://jira.hyperledger.org/browse/FAB-3458) Remove global vars in server command
* [5554406](https://github.com/hyperledger/fabric-ca/commit/5554406) [FAB-3458](https://jira.hyperledger.org/browse/FAB-3458) Remove global vars in client cmd
* [ddddc5c](https://github.com/hyperledger/fabric-ca/commit/ddddc5c) [FAB-5707](https://jira.hyperledger.org/browse/FAB-5707) Vendoring github.com/pkg/errors
* [253afb7](https://github.com/hyperledger/fabric-ca/commit/253afb7) [FAB-5794](https://jira.hyperledger.org/browse/FAB-5794) Fix some DB log messages
* [48e7be4](https://github.com/hyperledger/fabric-ca/commit/48e7be4) FAB-5749 Fix fabric-ca-server startup msg
* [77f76df](https://github.com/hyperledger/fabric-ca/commit/77f76df) [FAB-5389](https://jira.hyperledger.org/browse/FAB-5389) gencsr command for fabric-ca-client
* [da97bc8](https://github.com/hyperledger/fabric-ca/commit/da97bc8) [FAB-5678](https://jira.hyperledger.org/browse/FAB-5678) Improve SQL not found error message
* [0d9c927](https://github.com/hyperledger/fabric-ca/commit/0d9c927) [ FAB-3581 ] Updated error message for multica fvt
* [b630717](https://github.com/hyperledger/fabric-ca/commit/b630717) [FAB-5761](https://jira.hyperledger.org/browse/FAB-5761) Fix a couple of debug messages
* [7dd5747](https://github.com/hyperledger/fabric-ca/commit/7dd5747) [ FAB-3982 ] TLS copy tools for fabric-ca tests
* [9300caa](https://github.com/hyperledger/fabric-ca/commit/9300caa) [FAB-3581](https://jira.hyperledger.org/browse/FAB-3581) Improve error handling (#3)
* [9966ce5](https://github.com/hyperledger/fabric-ca/commit/9966ce5) [FAB-3581](https://jira.hyperledger.org/browse/FAB-3581) Improve error handling (#2)
* [00caa9c](https://github.com/hyperledger/fabric-ca/commit/00caa9c) [FAB-3581](https://jira.hyperledger.org/browse/FAB-3581) Improve error handling (#1)
* [a070182](https://github.com/hyperledger/fabric-ca/commit/a070182) [FAB-4973](https://jira.hyperledger.org/browse/FAB-4973) Add TLS profile to default config
* [c6fc16b](https://github.com/hyperledger/fabric-ca/commit/c6fc16b) [FAB-3924](https://jira.hyperledger.org/browse/FAB-3924) Improve test coverage of lib
* [9895f6b](https://github.com/hyperledger/fabric-ca/commit/9895f6b) [ FAB-5278 ] Multi-ca fvt test
* [919d632](https://github.com/hyperledger/fabric-ca/commit/919d632) [ FAB-5254 ] Add logging for haproxy
* [77f573c](https://github.com/hyperledger/fabric-ca/commit/77f573c) [ FAB-5251 ] Changes to optimize fvt tests
* [748467f](https://github.com/hyperledger/fabric-ca/commit/748467f) [FAB-5510](https://jira.hyperledger.org/browse/FAB-5510) Mask the identity password in the log
* [fa60287](https://github.com/hyperledger/fabric-ca/commit/fa60287) FAB-5530 Vendor latest version of bccsp
* [72e010e](https://github.com/hyperledger/fabric-ca/commit/72e010e) [ FAB-5009 ] Update intermediate CA test
* [d24c05c](https://github.com/hyperledger/fabric-ca/commit/d24c05c) [ FAB-5434 ] Fix mysql internal_DB permissions
* [64676ae](https://github.com/hyperledger/fabric-ca/commit/64676ae) [FAB-5512](https://jira.hyperledger.org/browse/FAB-5512) Fix typos in fabric-ca-client package
* [f54aaf2](https://github.com/hyperledger/fabric-ca/commit/f54aaf2) [FAB-3026](https://jira.hyperledger.org/browse/FAB-3026) OOM for very large CRLs
* [3ba0088](https://github.com/hyperledger/fabric-ca/commit/3ba0088) [FAB-4844](https://jira.hyperledger.org/browse/FAB-4844) Store MSP intermediatecerts
* [5d131b7](https://github.com/hyperledger/fabric-ca/commit/5d131b7) [FAB-5250](https://jira.hyperledger.org/browse/FAB-5250) Add version command to server and client
* [2abc451](https://github.com/hyperledger/fabric-ca/commit/2abc451) [FAB-4409](https://jira.hyperledger.org/browse/FAB-4409) update vendored package cfssl
* [dd60a58](https://github.com/hyperledger/fabric-ca/commit/dd60a58) [FAB-3662](https://jira.hyperledger.org/browse/FAB-3662) Document DB version support
* [d31c0d7](https://github.com/hyperledger/fabric-ca/commit/d31c0d7) [FAB-5239](https://jira.hyperledger.org/browse/FAB-5239) LDAP reconnect for idle timeout
* [e03673c](https://github.com/hyperledger/fabric-ca/commit/e03673c) [FAB-3051](https://jira.hyperledger.org/browse/FAB-3051) Input validation on CSR fields
* [4e5c55f](https://github.com/hyperledger/fabric-ca/commit/4e5c55f) [FAB-4915](https://jira.hyperledger.org/browse/FAB-4915) Fix timing bug in server stop
* [bc2b642](https://github.com/hyperledger/fabric-ca/commit/bc2b642) [FAB-5434](https://jira.hyperledger.org/browse/FAB-5434) Fix mysql config in fvt image
* [086cc2f](https://github.com/hyperledger/fabric-ca/commit/086cc2f) [FAB-4126](https://jira.hyperledger.org/browse/FAB-4126) Convert fatal message to error
* [b9e8a8e](https://github.com/hyperledger/fabric-ca/commit/b9e8a8e) [FAB-5334](https://jira.hyperledger.org/browse/FAB-5334) Intermediate CA does not copy BCCSP config

## v1.0.4
Tue Oct 31 15:14:49 EDT 2017

* [65686e9](https://github.com/hyperledger/fabric-ca/commit/65686e9) [FAB-6704](https://jira.hyperledger.org/browse/FAB-6704) Fix garbled listen message on startup
* [5149604](https://github.com/hyperledger/fabric-ca/commit/5149604) [FAB-6624](https://jira.hyperledger.org/browse/FAB-6624) Update vendored version of bccsp
* [c5d399d](https://github.com/hyperledger/fabric-ca/commit/c5d399d) [FAB-6643](https://jira.hyperledger.org/browse/FAB-6643) Add ci.properties file
* [9ceec62](https://github.com/hyperledger/fabric-ca/commit/9ceec62) Update URL for MAINTAINERS source
* [19280b6](https://github.com/hyperledger/fabric-ca/commit/19280b6) [FAB-6377](https://jira.hyperledger.org/browse/FAB-6377) Prepare fabric-ca for v1.0.4 release

## v1.0.3
Tue Oct  3 05:21:02 EDT 2017

* [897e99e](https://github.com/hyperledger/fabric-ca/commit/897e99e) [FAB-6360](https://jira.hyperledger.org/browse/FAB-6360) Update license text in README
* [cc1a524](https://github.com/hyperledger/fabric-ca/commit/cc1a524)  [FAB-6247](https://jira.hyperledger.org/browse/FAB-6247) Sanitize debug messages
* [4c9f3d9](https://github.com/hyperledger/fabric-ca/commit/4c9f3d9) [FAB-5994](https://jira.hyperledger.org/browse/FAB-5994) Prepare fabric-ca for v1.0.3 release

## v1.0.2
Thu Aug 31 04:22:27 EDT 2017

* [3066136](https://github.com/hyperledger/fabric-ca/commit/3066136) [FAB-5794](https://jira.hyperledger.org/browse/FAB-5794) Mask credentials in debug messages
* [00700da](https://github.com/hyperledger/fabric-ca/commit/00700da) [FAB-5653](https://jira.hyperledger.org/browse/FAB-5653) Prepare fabric-ca for v1.0.2 release

## v1.0.1
Mon Jul 31 05:57:59 EDT 2017

* [748467f](https://github.com/hyperledger/fabric-ca/commit/748467f) [FAB-5510](https://jira.hyperledger.org/browse/FAB-5510) Mask the identity password in the log
* [fa60287](https://github.com/hyperledger/fabric-ca/commit/fa60287) [FAB-5530](https://jira.hyperledger.org/browse/FAB-5530) Vendor latest version of bccsp
* [72e010e](https://github.com/hyperledger/fabric-ca/commit/72e010e) [ [FAB-5009](https://jira.hyperledger.org/browse/FAB-5009) ] Update intermediate CA test
* [d24c05c](https://github.com/hyperledger/fabric-ca/commit/d24c05c) [ [FAB-5434](https://jira.hyperledger.org/browse/FAB-5434) ] Fix mysql internal_DB permissions
* [f54aaf2](https://github.com/hyperledger/fabric-ca/commit/f54aaf2) [FAB-3026](https://jira.hyperledger.org/browse/FAB-3026) OOM for very large CRLs
* [3ba0088](https://github.com/hyperledger/fabric-ca/commit/3ba0088) [FAB-4844](https://jira.hyperledger.org/browse/FAB-4844) Store MSP intermediatecerts
* [2abc451](https://github.com/hyperledger/fabric-ca/commit/2abc451) [FAB-4409](https://jira.hyperledger.org/browse/FAB-4409) update vendored package cfssl
* [dd60a58](https://github.com/hyperledger/fabric-ca/commit/dd60a58) [FAB-3662](https://jira.hyperledger.org/browse/FAB-3662) Document DB version support
* [d31c0d7](https://github.com/hyperledger/fabric-ca/commit/d31c0d7) [FAB-5239](https://jira.hyperledger.org/browse/FAB-5239) LDAP reconnect for idle timeout
* [e03673c](https://github.com/hyperledger/fabric-ca/commit/e03673c) [FAB-3051](https://jira.hyperledger.org/browse/FAB-3051) Input validation on CSR fields
* [4e5c55f](https://github.com/hyperledger/fabric-ca/commit/4e5c55f) [FAB-4915](https://jira.hyperledger.org/browse/FAB-4915) Fix timing bug in server stop
* [bc2b642](https://github.com/hyperledger/fabric-ca/commit/bc2b642) [FAB-5434](https://jira.hyperledger.org/browse/FAB-5434) Fix mysql config in fvt image
* [086cc2f](https://github.com/hyperledger/fabric-ca/commit/086cc2f) [FAB-4126](https://jira.hyperledger.org/browse/FAB-4126) Convert fatal message to error
* [b9e8a8e](https://github.com/hyperledger/fabric-ca/commit/b9e8a8e) [FAB-5334](https://jira.hyperledger.org/browse/FAB-5334) Intermediate CA does not copy BCCSP config
* [b2679c9](https://github.com/hyperledger/fabric-ca/commit/b2679c9) [FAB-5531](https://jira.hyperledger.org/browse/FAB-5531) Create 1.0.1 fabric-ca release
* [a21585d](https://github.com/hyperledger/fabric-ca/commit/a21585d) [FAB-5071](https://jira.hyperledger.org/browse/FAB-5071) Prepare for v1.0.1 release

## v1.0.0
Tue Jul 11 16:38:28 CEST 2017

* [2a65467](https://github.com/hyperledger/fabric-ca/commit/2a65467) [FAB-5203](https://jira.hyperledger.org/browse/FAB-5203) Store hash of password in DB
* [e52c670](https://github.com/hyperledger/fabric-ca/commit/e52c670) [FAB-5188](https://jira.hyperledger.org/browse/FAB-5188) Fix password conversion bug
* [f013d54](https://github.com/hyperledger/fabric-ca/commit/f013d54) [FAB-4997](https://jira.hyperledger.org/browse/FAB-4997) Typo - VerfiyClientCertIfGiven
* [ecb50ed](https://github.com/hyperledger/fabric-ca/commit/ecb50ed) [FAB-4993](https://jira.hyperledger.org/browse/FAB-4993) Incorrect key usage for issued certs
* [756ba98](https://github.com/hyperledger/fabric-ca/commit/756ba98) FAB-4520 prepare for rc2 development

## v1.0.0-rc1
Fri Jun 23 14:47:44 EDT 2017

* [2a00490](https://github.com/hyperledger/fabric-ca/commit/2a00490) FAB-4520 1.0.0-rc1 release
* [7d4cd37](https://github.com/hyperledger/fabric-ca/commit/7d4cd37) [FAB-4499](https://jira.hyperledger.org/browse/FAB-4499) Reformatting doc
* [5200f07](https://github.com/hyperledger/fabric-ca/commit/5200f07) [FAB-4841](https://jira.hyperledger.org/browse/FAB-4841) Doc no support for encrypted keys
* [a71e0f5](https://github.com/hyperledger/fabric-ca/commit/a71e0f5) [FAB-4887](https://jira.hyperledger.org/browse/FAB-4887) Server creates unused MSP directory
* [699e1b9](https://github.com/hyperledger/fabric-ca/commit/699e1b9) [FAB-4864](https://jira.hyperledger.org/browse/FAB-4864) Doc update for max file descriptors
* [5b7790f](https://github.com/hyperledger/fabric-ca/commit/5b7790f) [FAB-4868](https://jira.hyperledger.org/browse/FAB-4868) Verify key has 'Cert Sign' usage
* [4f4264d](https://github.com/hyperledger/fabric-ca/commit/4f4264d) [FAB-4865](https://jira.hyperledger.org/browse/FAB-4865) NPE occurs on LoadIdentity
* [82fad13](https://github.com/hyperledger/fabric-ca/commit/82fad13) [FAB-4856](https://jira.hyperledger.org/browse/FAB-4856) Only allow TLS 1.2
* [d263557](https://github.com/hyperledger/fabric-ca/commit/d263557) FAB-4861 fix various doc format issues
* [313d945](https://github.com/hyperledger/fabric-ca/commit/313d945) [FAB-4826](https://jira.hyperledger.org/browse/FAB-4826) Token-based auth issue to int server
* [7e72c6e](https://github.com/hyperledger/fabric-ca/commit/7e72c6e) FAB-3963 add missing license headers
* [cef4f1f](https://github.com/hyperledger/fabric-ca/commit/cef4f1f) [FAB-4567](https://jira.hyperledger.org/browse/FAB-4567) Fix for id attributes security issue
* [989b563](https://github.com/hyperledger/fabric-ca/commit/989b563) FAB-4572 add missing license headers
* [1424b33](https://github.com/hyperledger/fabric-ca/commit/1424b33) [FAB-4515](https://jira.hyperledger.org/browse/FAB-4515) Fix concurrency issue with enroll
* [ef110bc](https://github.com/hyperledger/fabric-ca/commit/ef110bc) [FAB-4507](https://jira.hyperledger.org/browse/FAB-4507) Token-based authentication issue
* [037b407](https://github.com/hyperledger/fabric-ca/commit/037b407) [FAB-4211](https://jira.hyperledger.org/browse/FAB-4211) WIP: Allow zero date values MySQL
* [60f4fae](https://github.com/hyperledger/fabric-ca/commit/60f4fae) [FAB-4484](https://jira.hyperledger.org/browse/FAB-4484) Fix link to user guide
* [56cca2e](https://github.com/hyperledger/fabric-ca/commit/56cca2e) FAB-4382 prepare for 1.0.0-rc1 development
* [6b8c55d](https://github.com/hyperledger/fabric-ca/commit/6b8c55d) [FAB-4372](https://jira.hyperledger.org/browse/FAB-4372) Value of attributes are ignored

## v1.0.0-beta
Wed Jun  7 08:10:56 EDT 2017

* [c9372be](https://github.com/hyperledger/fabric-ca/commit/c9372be) [FAB-4404](https://jira.hyperledger.org/browse/FAB-4404) Adding CA to server restricted on DN
* [03d860d](https://github.com/hyperledger/fabric-ca/commit/03d860d) [FAB-3415](https://jira.hyperledger.org/browse/FAB-3415) Improve LDAP usage and error handling
* [f963ce8](https://github.com/hyperledger/fabric-ca/commit/f963ce8) [FAB-4093](https://jira.hyperledger.org/browse/FAB-4093) Fix the TLS client using BCCSP
* [22dc710](https://github.com/hyperledger/fabric-ca/commit/22dc710) [FAB-3228](https://jira.hyperledger.org/browse/FAB-3228) Fix/clarify CA pathlen constraints
* [fdcf1c7](https://github.com/hyperledger/fabric-ca/commit/fdcf1c7) [FAB-4311](https://jira.hyperledger.org/browse/FAB-4311) Fix duplicated fabric-ca config item
* [9ce8536](https://github.com/hyperledger/fabric-ca/commit/9ce8536) [FAB-4307](https://jira.hyperledger.org/browse/FAB-4307) add missing CCBY license to all docs
* [42f48d2](https://github.com/hyperledger/fabric-ca/commit/42f48d2) [FAB-4188](https://jira.hyperledger.org/browse/FAB-4188) Documentation updates
* [120b139](https://github.com/hyperledger/fabric-ca/commit/120b139) [FAB-3011](https://jira.hyperledger.org/browse/FAB-3011) Fix max enrollment checking logic
* [5987a8e](https://github.com/hyperledger/fabric-ca/commit/5987a8e) [FAB-3683](https://jira.hyperledger.org/browse/FAB-3683) SIGSEGV seen for MySQL empty certfiles
* [0f73bdc](https://github.com/hyperledger/fabric-ca/commit/0f73bdc) [FAB-4209](https://jira.hyperledger.org/browse/FAB-4209) Fix JSON error in swagger doc
* [1777996](https://github.com/hyperledger/fabric-ca/commit/1777996) [FAB-4097](https://jira.hyperledger.org/browse/FAB-4097) Fix getcacert client command config
* [05749b7](https://github.com/hyperledger/fabric-ca/commit/05749b7) [FAB-4180](https://jira.hyperledger.org/browse/FAB-4180) fix misspell doc title issue
* [efd537e](https://github.com/hyperledger/fabric-ca/commit/efd537e) [FAB-1989](https://jira.hyperledger.org/browse/FAB-1989) Fix leaking authority to delegates
* [791f2ae](https://github.com/hyperledger/fabric-ca/commit/791f2ae) [FAB-3759](https://jira.hyperledger.org/browse/FAB-3759) Fix the msg shown when TLS certs are missing
* [92e13cb](https://github.com/hyperledger/fabric-ca/commit/92e13cb) [FAB-3971](https://jira.hyperledger.org/browse/FAB-3971) Register id with multiple attrs
* [0dcd514](https://github.com/hyperledger/fabric-ca/commit/0dcd514) [FAB-2919](https://jira.hyperledger.org/browse/FAB-2919) Workaround for panic due to lib bug
* [dfb555f](https://github.com/hyperledger/fabric-ca/commit/dfb555f) [FAB-3425](https://jira.hyperledger.org/browse/FAB-3425) Fix typo in error messages
* [1be793d](https://github.com/hyperledger/fabric-ca/commit/1be793d) [FAB-3734](https://jira.hyperledger.org/browse/FAB-3734) Fix default expiration times
* [ac8695b](https://github.com/hyperledger/fabric-ca/commit/ac8695b) [FAB-4141](https://jira.hyperledger.org/browse/FAB-4141) Default CA lookup fails
* [4559758](https://github.com/hyperledger/fabric-ca/commit/4559758) [ [FAB-3924](https://jira.hyperledger.org/browse/FAB-3924) ] - Additional test coverage for tcert
* [a5ab60d](https://github.com/hyperledger/fabric-ca/commit/a5ab60d) [FAB-3630](https://jira.hyperledger.org/browse/FAB-3630) enable RTD build process on fabric-ca
* [99fd112](https://github.com/hyperledger/fabric-ca/commit/99fd112) [FAB-4017](https://jira.hyperledger.org/browse/FAB-4017) Duplicate flags registered for 'Hosts'
* [7870c73](https://github.com/hyperledger/fabric-ca/commit/7870c73) [FAB-4127](https://jira.hyperledger.org/browse/FAB-4127) remove vendored test file
* [6b7fd0e](https://github.com/hyperledger/fabric-ca/commit/6b7fd0e) [FAB-4109](https://jira.hyperledger.org/browse/FAB-4109) add license headers to scripts
* [e9da2c7](https://github.com/hyperledger/fabric-ca/commit/e9da2c7) [FAB-3883](https://jira.hyperledger.org/browse/FAB-3883) Intermediate CA restriction on CN
* [7d680bb](https://github.com/hyperledger/fabric-ca/commit/7d680bb) [FAB-4096](https://jira.hyperledger.org/browse/FAB-4096) Remove openldap tarball
* [addef8a](https://github.com/hyperledger/fabric-ca/commit/addef8a) [FAB-3827](https://jira.hyperledger.org/browse/FAB-3827) CA TLS support broke with BCCSP keys
* [2560ffd](https://github.com/hyperledger/fabric-ca/commit/2560ffd) [FAB-4015](https://jira.hyperledger.org/browse/FAB-4015) Fix -M option of fabric-ca-client
* [01d2dd0](https://github.com/hyperledger/fabric-ca/commit/01d2dd0) [FAB-2976](https://jira.hyperledger.org/browse/FAB-2976) Server shouldn't create dup affiliations
* [804eb19](https://github.com/hyperledger/fabric-ca/commit/804eb19) [FAB-4024](https://jira.hyperledger.org/browse/FAB-4024) Update vendor for Fabric flogging
* [88dc694](https://github.com/hyperledger/fabric-ca/commit/88dc694) [ [FAB-4016](https://jira.hyperledger.org/browse/FAB-4016) ] fix run_fvt_test redirect error
* [c200c02](https://github.com/hyperledger/fabric-ca/commit/c200c02) [FAB-3924](https://jira.hyperledger.org/browse/FAB-3924) fabric-ca-client test coverage >85%
* [0ee3115](https://github.com/hyperledger/fabric-ca/commit/0ee3115) [FAB-3490](https://jira.hyperledger.org/browse/FAB-3490) fix revoked user enrollment
* [30d5ecf](https://github.com/hyperledger/fabric-ca/commit/30d5ecf) [FAB-3974](https://jira.hyperledger.org/browse/FAB-3974) Fix server crash on PKCS8 private key
* [de4187b](https://github.com/hyperledger/fabric-ca/commit/de4187b) [FAB-3845](https://jira.hyperledger.org/browse/FAB-3845) Configuration of intermediate CA via CLI
* [2b1c309](https://github.com/hyperledger/fabric-ca/commit/2b1c309) [FAB-3100](https://jira.hyperledger.org/browse/FAB-3100) Fix panic in server start
* [52f09ed](https://github.com/hyperledger/fabric-ca/commit/52f09ed) [FAB-3121](https://jira.hyperledger.org/browse/FAB-3121) Improve Intermediate CA error message
* [9bfde7e](https://github.com/hyperledger/fabric-ca/commit/9bfde7e) [FAB-3958](https://jira.hyperledger.org/browse/FAB-3958) Update fabric-ca vendor for BCCSP
* [4d657bc](https://github.com/hyperledger/fabric-ca/commit/4d657bc) [FAB-1823](https://jira.hyperledger.org/browse/FAB-1823) Perform validation on CA certificate
* [cb7a109](https://github.com/hyperledger/fabric-ca/commit/cb7a109) [FAB-3924](https://jira.hyperledger.org/browse/FAB-3924) Improved test coverage lib/tls package
* [bdefc3a](https://github.com/hyperledger/fabric-ca/commit/bdefc3a) [FAB-3924](https://jira.hyperledger.org/browse/FAB-3924) Improved test coverage util package
* [2904d1c](https://github.com/hyperledger/fabric-ca/commit/2904d1c) [FAB-3918](https://jira.hyperledger.org/browse/FAB-3918) Update to baseimage v0.3.1
* [f2df727](https://github.com/hyperledger/fabric-ca/commit/f2df727) [FAB-3895](https://jira.hyperledger.org/browse/FAB-3895) add scripts/changelog.sh
* [52c503b](https://github.com/hyperledger/fabric-ca/commit/52c503b) Prepare for alpha3 development
* [94ced50](https://github.com/hyperledger/fabric-ca/commit/94ced50) [FAB-3574](https://jira.hyperledger.org/browse/FAB-3574) Finish fix of multi CA config
* [9e41d59](https://github.com/hyperledger/fabric-ca/commit/9e41d59) [FAB-3743](https://jira.hyperledger.org/browse/FAB-3743) Update private key format

## v1.0.0-alpha2
Fri May 12 15:29:02 EDT 2017


* [0650f04](https://github.com/hyperledger/fabric-ca/commit/0650f04) [FAB-3895](https://jira.hyperledger.org/browse/FAB-3895) add scripts/changelog.sh
* [c1bb6c4](https://github.com/hyperledger/fabric-ca/commit/c1bb6c4) [FAB-3574](https://jira.hyperledger.org/browse/FAB-3574) Fix missing CA config values logic
* [34ec53e](https://github.com/hyperledger/fabric-ca/commit/34ec53e) [FAB-3574](https://jira.hyperledger.org/browse/FAB-3574) Perform deep copy of config file
* [2fa6143](https://github.com/hyperledger/fabric-ca/commit/2fa6143) [FAB-3622](https://jira.hyperledger.org/browse/FAB-3622) Update API with JSON tag for 'CAName'
* [a010ec8](https://github.com/hyperledger/fabric-ca/commit/a010ec8) [FAB-3629](https://jira.hyperledger.org/browse/FAB-3629) Move Fabric-CA doc to fabric-ca repo
* [0624550](https://github.com/hyperledger/fabric-ca/commit/0624550) [FAB-3191](https://jira.hyperledger.org/browse/FAB-3191) Ability to enable cpu/heap profiling
* [15bc87e](https://github.com/hyperledger/fabric-ca/commit/15bc87e) [ [FAB-1892](https://jira.hyperledger.org/browse/FAB-1892) ] - Add LDAP to fvt test image
* [90bd1b6](https://github.com/hyperledger/fabric-ca/commit/90bd1b6) [ [FAB-3554](https://jira.hyperledger.org/browse/FAB-3554) ] Add make target for local CI tests
* [50bbfc7](https://github.com/hyperledger/fabric-ca/commit/50bbfc7) [FAB-3050](https://jira.hyperledger.org/browse/FAB-3050) Document serial number of CSR
* [34ddbee](https://github.com/hyperledger/fabric-ca/commit/34ddbee) [FAB-3433](https://jira.hyperledger.org/browse/FAB-3433) Short names for flags for revoke command
* [ecd796a](https://github.com/hyperledger/fabric-ca/commit/ecd796a) [FAB-3518](https://jira.hyperledger.org/browse/FAB-3518) Fix fabric-ca-server build failure
* [50c540e](https://github.com/hyperledger/fabric-ca/commit/50c540e) [FAB-3503](https://jira.hyperledger.org/browse/FAB-3503) Wrong MSP keystore directory location
* [610a3b9](https://github.com/hyperledger/fabric-ca/commit/610a3b9) [ [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) ] revert blank CA name for tests
* [ab83a2e](https://github.com/hyperledger/fabric-ca/commit/ab83a2e) [FAB-864](https://jira.hyperledger.org/browse/FAB-864) Vendor BCCSP from fabric to fabric-ca
* [0d272e6](https://github.com/hyperledger/fabric-ca/commit/0d272e6) [FAB-2601](https://jira.hyperledger.org/browse/FAB-2601) Fabric CA BCCSP integration
* [9c4acfd](https://github.com/hyperledger/fabric-ca/commit/9c4acfd) [FAB-2601](https://jira.hyperledger.org/browse/FAB-2601) Fabric CA BCCSP integration utilities
* [1583adf](https://github.com/hyperledger/fabric-ca/commit/1583adf) [FAB-3369](https://jira.hyperledger.org/browse/FAB-3369) Added missing slice config options
* [5610d33](https://github.com/hyperledger/fabric-ca/commit/5610d33) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Start multiple default CA instances
* [c131944](https://github.com/hyperledger/fabric-ca/commit/c131944) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Directing traffic to specific CAs
* [d53f934](https://github.com/hyperledger/fabric-ca/commit/d53f934) [FAB-3396](https://jira.hyperledger.org/browse/FAB-3396) Fixed "index out of range" error
* [3ab84cb](https://github.com/hyperledger/fabric-ca/commit/3ab84cb) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Loading multiple CAs from config files
* [b4ce73f](https://github.com/hyperledger/fabric-ca/commit/b4ce73f) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Create CA configuration struct
* [d7a5c29](https://github.com/hyperledger/fabric-ca/commit/d7a5c29) [FAB-2896](https://jira.hyperledger.org/browse/FAB-2896) Support multiple CAs - new CA struct
* [8976d7b](https://github.com/hyperledger/fabric-ca/commit/8976d7b) [ [FAB-1673](https://jira.hyperledger.org/browse/FAB-1673) ] Integrate fabric/cop fvt in CI
* [a13fc7c](https://github.com/hyperledger/fabric-ca/commit/a13fc7c) [FAB-3107](https://jira.hyperledger.org/browse/FAB-3107) Use 'identity' instead of 'user'
* [c93266f](https://github.com/hyperledger/fabric-ca/commit/c93266f) [FAB-2841](https://jira.hyperledger.org/browse/FAB-2841) Revoke fails if aki,serial and eid are set
* [4f472c4](https://github.com/hyperledger/fabric-ca/commit/4f472c4) [FAB-2868](https://jira.hyperledger.org/browse/FAB-2868) Return 401 error for restricted operations
* [2672dd3](https://github.com/hyperledger/fabric-ca/commit/2672dd3) [ [FAB-2909](https://jira.hyperledger.org/browse/FAB-2909) ] Fix failing UT for file name too long
* [75f402c](https://github.com/hyperledger/fabric-ca/commit/75f402c) [FAB-1463](https://jira.hyperledger.org/browse/FAB-1463) Add TLS support to CA server's LDAP client
* [5dd0561](https://github.com/hyperledger/fabric-ca/commit/5dd0561) [FAB-2597](https://jira.hyperledger.org/browse/FAB-2597) Del cfssl prefix from REST APIs
* [7539e33](https://github.com/hyperledger/fabric-ca/commit/7539e33) [FAB-2955](https://jira.hyperledger.org/browse/FAB-2955) Set max open conn for sqlite to 1
* [6d5ae41](https://github.com/hyperledger/fabric-ca/commit/6d5ae41) [FAB-3061](https://jira.hyperledger.org/browse/FAB-3061) Persist the ca.name
* [de5f4bd](https://github.com/hyperledger/fabric-ca/commit/de5f4bd) [FAB-3174](https://jira.hyperledger.org/browse/FAB-3174) Fix compile error in tls.go
* [7b356c9](https://github.com/hyperledger/fabric-ca/commit/7b356c9) [FAB-1854](https://jira.hyperledger.org/browse/FAB-1854) Add file names with colons to gitignore
* [7f85469](https://github.com/hyperledger/fabric-ca/commit/7f85469) Handle string slices in config appropriately
* [1c68d07](https://github.com/hyperledger/fabric-ca/commit/1c68d07) [FAB-1467](https://jira.hyperledger.org/browse/FAB-1467) Allow make without docker
* [f0f86b7](https://github.com/hyperledger/fabric-ca/commit/f0f86b7) Client should check TLS cert for valid dates
* [b31da6b](https://github.com/hyperledger/fabric-ca/commit/b31da6b) Fix affiliation hierarchy checking during revoke
* [db76a08](https://github.com/hyperledger/fabric-ca/commit/db76a08) [FAB-3004](https://jira.hyperledger.org/browse/FAB-3004) Remove extraneous flags
* [7a4a7f4](https://github.com/hyperledger/fabric-ca/commit/7a4a7f4) [FAB-3038](https://jira.hyperledger.org/browse/FAB-3038) Fix certificate look up logic
* [4c3189b](https://github.com/hyperledger/fabric-ca/commit/4c3189b) [FAB-3007](https://jira.hyperledger.org/browse/FAB-3007):Make CA name required
* [855036c](https://github.com/hyperledger/fabric-ca/commit/855036c) [FAB-3010](https://jira.hyperledger.org/browse/FAB-3010) Update the fabric-ca README
* [ee2ec59](https://github.com/hyperledger/fabric-ca/commit/ee2ec59) [FAB-2668](https://jira.hyperledger.org/browse/FAB-2668) Ensure revocation updates DB
* [d9a1724](https://github.com/hyperledger/fabric-ca/commit/d9a1724) [FAB-3020](https://jira.hyperledger.org/browse/FAB-3020) fix client-server-flow doc typo
* [a8f1d79](https://github.com/hyperledger/fabric-ca/commit/a8f1d79) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Update enrollment test
* [e909700](https://github.com/hyperledger/fabric-ca/commit/e909700) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Update roundrobin test
* [05cbac8](https://github.com/hyperledger/fabric-ca/commit/05cbac8) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Update reregister test
* [7b9eb18](https://github.com/hyperledger/fabric-ca/commit/7b9eb18) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) - Update reenroll test
* [bfacafe](https://github.com/hyperledger/fabric-ca/commit/bfacafe) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) - Update group test
* [4456f65](https://github.com/hyperledger/fabric-ca/commit/4456f65) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) - Remove local install of fabric prereq
* [06bb12f](https://github.com/hyperledger/fabric-ca/commit/06bb12f) [FAB-2572](https://jira.hyperledger.org/browse/FAB-2572) Update client/server TLS setting
* [20a1b7a](https://github.com/hyperledger/fabric-ca/commit/20a1b7a) [FAB-](https://jira.hyperledger.org/browse/FAB-)[2571] use variable database name
* [4997ae7](https://github.com/hyperledger/fabric-ca/commit/4997ae7) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Generate config for both init and start
* [5a07ff7](https://github.com/hyperledger/fabric-ca/commit/5a07ff7) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Change client/server executable names
* [d10fd42](https://github.com/hyperledger/fabric-ca/commit/d10fd42) [FAB-2571](https://jira.hyperledger.org/browse/FAB-2571) Create docker image for fvt testing
* [54a8729](https://github.com/hyperledger/fabric-ca/commit/54a8729) Delete obsolete authentication test
* [f6fc6e8](https://github.com/hyperledger/fabric-ca/commit/f6fc6e8) Update run_ldap library directory for [FAB-1485](https://jira.hyperledger.org/browse/FAB-1485)
* [bd594b5](https://github.com/hyperledger/fabric-ca/commit/bd594b5) Failing util_test.go -- need to unset CA_CFG_PATH
* [a64ea74](https://github.com/hyperledger/fabric-ca/commit/a64ea74) Don't print usage message for non-usage errors
* [055cdc5](https://github.com/hyperledger/fabric-ca/commit/055cdc5) Improvement to TLS configurations
* [4651512](https://github.com/hyperledger/fabric-ca/commit/4651512) [FAB-2866](https://jira.hyperledger.org/browse/FAB-2866): Export new and load Identity methods
* [2b9daa3](https://github.com/hyperledger/fabric-ca/commit/2b9daa3) Case sensitivity for MySQL users table
* [e9bc7ff](https://github.com/hyperledger/fabric-ca/commit/e9bc7ff) Revoked user should not be able to make requests
* [684e63e](https://github.com/hyperledger/fabric-ca/commit/684e63e) Fix [FAB-1485](https://jira.hyperledger.org/browse/FAB-1485)
* [fb3a4a9](https://github.com/hyperledger/fabric-ca/commit/fb3a4a9) Prepare for post-alpha development
* [2360c26](https://github.com/hyperledger/fabric-ca/commit/2360c26) Fix init information in config.go
* [4325538](https://github.com/hyperledger/fabric-ca/commit/4325538) Rename occurences of COP to CA

## v1.0.0-alpha
March 16, 2017

* [b587a48](https://github.com/hyperledger/fabric-ca/commit/b587a48) Release v1.0.0-alpha
* [382c65b](https://github.com/hyperledger/fabric-ca/commit/382c65b) BCCSP InitFactories not called in fabric-ca-client
* [9132e6d](https://github.com/hyperledger/fabric-ca/commit/9132e6d) Client home has incorrect path when env vars set
* [12b0e1b](https://github.com/hyperledger/fabric-ca/commit/12b0e1b) Do not restrict fabric-ca client config to yml
* [46bbd8c](https://github.com/hyperledger/fabric-ca/commit/46bbd8c) enroll req sent with an invalid auth header should fail
* [cb9fae9](https://github.com/hyperledger/fabric-ca/commit/cb9fae9) Fix linting error with lib/server.go
* [e183a88](https://github.com/hyperledger/fabric-ca/commit/e183a88) Changes to make auth type an enum
* [808a15d](https://github.com/hyperledger/fabric-ca/commit/808a15d) Affiliation table clean up
* [c7b482e](https://github.com/hyperledger/fabric-ca/commit/c7b482e) Add support for -M option for enroll/reenroll
* [2e51747](https://github.com/hyperledger/fabric-ca/commit/2e51747) Add support for client getcacert command
* [074ebab](https://github.com/hyperledger/fabric-ca/commit/074ebab) Mask passwords in the log entries
* [b09448e](https://github.com/hyperledger/fabric-ca/commit/b09448e) Tests to check db file is created in right dir
* [df922a1](https://github.com/hyperledger/fabric-ca/commit/df922a1) Remove global variables in lib
* [ee4f92a](https://github.com/hyperledger/fabric-ca/commit/ee4f92a) Remove cli from fabric-ca
* [403080d](https://github.com/hyperledger/fabric-ca/commit/403080d) Improvements to revoke client side command
* [cd8802b](https://github.com/hyperledger/fabric-ca/commit/cd8802b) Registrar can configure max enrollment for user
* [35c5648](https://github.com/hyperledger/fabric-ca/commit/35c5648) Replace group with affiliation for users
* [7c44a8f](https://github.com/hyperledger/fabric-ca/commit/7c44a8f) Enrollment info part of client config
* [4d9e2e3](https://github.com/hyperledger/fabric-ca/commit/4d9e2e3) Registration request part of client config
* [c2bd335](https://github.com/hyperledger/fabric-ca/commit/c2bd335) Vendor fetch bccsp from fabric
* [9195741](https://github.com/hyperledger/fabric-ca/commit/9195741) TLS testcases and process file names client config
* [64e22bd](https://github.com/hyperledger/fabric-ca/commit/64e22bd) Base 64 encode/decode with padding
* [c3d00c3](https://github.com/hyperledger/fabric-ca/commit/c3d00c3) [FAB-2481](https://jira.hyperledger.org/browse/FAB-2481) cleanup files with suspicious permissions
* [87410b4](https://github.com/hyperledger/fabric-ca/commit/87410b4) Update fabric-ca-server UT main test
* [34ad615](https://github.com/hyperledger/fabric-ca/commit/34ad615) Docker image with client and server commands
* [3f8445a](https://github.com/hyperledger/fabric-ca/commit/3f8445a) Intermediate CA server support
* [d02bbe4](https://github.com/hyperledger/fabric-ca/commit/d02bbe4) Reflect to add server config flags
* [9ae96f2](https://github.com/hyperledger/fabric-ca/commit/9ae96f2) Revendor cfssl for fabricc-ca BCCSP integration
* [c280fa3](https://github.com/hyperledger/fabric-ca/commit/c280fa3) Fabric-CA bccsp integration for VerifyToken
* [98abc75](https://github.com/hyperledger/fabric-ca/commit/98abc75) Fix README.md
* [3ab50fc](https://github.com/hyperledger/fabric-ca/commit/3ab50fc) Pre-req for fabric-ca/fvt-test.
* [37b897b](https://github.com/hyperledger/fabric-ca/commit/37b897b) fabric-ca-client commands for cobra/viper CLI
* [fbccd13](https://github.com/hyperledger/fabric-ca/commit/fbccd13) Complete fabric-ca-server start command
* [9db14ab](https://github.com/hyperledger/fabric-ca/commit/9db14ab) Added revocation test
* [ee8ccef](https://github.com/hyperledger/fabric-ca/commit/ee8ccef) Added test for command line default port/addr
* [67c9491](https://github.com/hyperledger/fabric-ca/commit/67c9491) Add certificate validation test
* [41e6c52](https://github.com/hyperledger/fabric-ca/commit/41e6c52) Fix README.md
* [0243300](https://github.com/hyperledger/fabric-ca/commit/0243300) Add version-agnostic link to DB executable
* [2ff7ba5](https://github.com/hyperledger/fabric-ca/commit/2ff7ba5) Added docker-compose for running fvt tests
* [5a35b72](https://github.com/hyperledger/fabric-ca/commit/5a35b72) fabric-ca-server start for cobra/viper CLI
* [5f56827](https://github.com/hyperledger/fabric-ca/commit/5f56827) fabric-ca-server init command
* [33547ef](https://github.com/hyperledger/fabric-ca/commit/33547ef) Update swagger doc for fabric-ca server's APIs
* [f507e2d](https://github.com/hyperledger/fabric-ca/commit/f507e2d) Fix the config path env variable
* [c4e83c1](https://github.com/hyperledger/fabric-ca/commit/c4e83c1) fabric-ca-client command plumbing with cobra/viper
* [b0e45f5](https://github.com/hyperledger/fabric-ca/commit/b0e45f5) fabric-ca-server command plumbing with cobra/viper
* [1ec55b2](https://github.com/hyperledger/fabric-ca/commit/1ec55b2) Vendor cobra to use in fabric-ca CLI work
* [3b781fb](https://github.com/hyperledger/fabric-ca/commit/3b781fb) Added test for registrar delgation
* [5105f60](https://github.com/hyperledger/fabric-ca/commit/5105f60) COP Client Configuration File
* [6294c57](https://github.com/hyperledger/fabric-ca/commit/6294c57) Remove the fabric-ca docker directory
* [9fde6f4](https://github.com/hyperledger/fabric-ca/commit/9fde6f4) Added support for TLS; deleted trailing spaces
* [d8d192e](https://github.com/hyperledger/fabric-ca/commit/d8d192e) Directory restructure for Change 4383
* [daf28ad](https://github.com/hyperledger/fabric-ca/commit/daf28ad) Create swagger json for fabric-ca REST APIs
* [2ccb6d3](https://github.com/hyperledger/fabric-ca/commit/2ccb6d3) Fabric-CA throws NPE using config file to start
* [ffe7676](https://github.com/hyperledger/fabric-ca/commit/ffe7676) Added basic fvt tests and utilities
* [8511358](https://github.com/hyperledger/fabric-ca/commit/8511358) Fix overlooked rename to fabric-ca
* [05b0f1d](https://github.com/hyperledger/fabric-ca/commit/05b0f1d) [FAB-1652](https://jira.hyperledger.org/browse/FAB-1652) Use fabric-baseos instead of busybox
* [da88926](https://github.com/hyperledger/fabric-ca/commit/da88926) Remove errant .gitignore exclusion of "fabric-ca"
* [585467a](https://github.com/hyperledger/fabric-ca/commit/585467a) Remove references to cop from README
* [f5291e7](https://github.com/hyperledger/fabric-ca/commit/f5291e7) Change expose port in dockerfile from 8888 to 7054
* [a569df9](https://github.com/hyperledger/fabric-ca/commit/a569df9) Change the default port to 7054
* [aa5fb82](https://github.com/hyperledger/fabric-ca/commit/aa5fb82) Revendor fabric's bccsp into fabric-ca
* [79a2558](https://github.com/hyperledger/fabric-ca/commit/79a2558) [FAB-1338](https://jira.hyperledger.org/browse/FAB-1338): Fix configs after rename
* [606fbdc](https://github.com/hyperledger/fabric-ca/commit/606fbdc) COP BCCSP integration
* [8894989](https://github.com/hyperledger/fabric-ca/commit/8894989) Renaming from fabric-cop to fabric-ca
* [c676b70](https://github.com/hyperledger/fabric-ca/commit/c676b70) [FAB-1338](https://jira.hyperledger.org/browse/FAB-1338): Include all config and cert files
* [00fc126](https://github.com/hyperledger/fabric-ca/commit/00fc126) Fix util test to pass on Windows
* [bac392b](https://github.com/hyperledger/fabric-ca/commit/bac392b) Make sure cop.db is systematically deleted for testing.
* [88866f1](https://github.com/hyperledger/fabric-ca/commit/88866f1) Delete cop.db after running COP unit tests
* [4e6481c](https://github.com/hyperledger/fabric-ca/commit/4e6481c) COP UserRegistry Consolidation
* [1ee390f](https://github.com/hyperledger/fabric-ca/commit/1ee390f) Fix linting error
* [81097b9](https://github.com/hyperledger/fabric-ca/commit/81097b9) COP API simplification
* [ebb62e9](https://github.com/hyperledger/fabric-ca/commit/ebb62e9) The reenroll command is incorrect in README
* [f0af10a](https://github.com/hyperledger/fabric-ca/commit/f0af10a) Fix incorrect license header
* [a9ff4d4](https://github.com/hyperledger/fabric-ca/commit/a9ff4d4) Store COP enrollment artifacts in MSP friendly way
* [8a95c35](https://github.com/hyperledger/fabric-ca/commit/8a95c35) Added missing CONTRIBUTING and MAINTAINERS files
* [e1fbfbf](https://github.com/hyperledger/fabric-ca/commit/e1fbfbf) Improve docker build/experience
* [a5666ff](https://github.com/hyperledger/fabric-ca/commit/a5666ff) Process file names in config file correctly
* [8e0b628](https://github.com/hyperledger/fabric-ca/commit/8e0b628) [FAB-1546](https://jira.hyperledger.org/browse/FAB-1546)"make ldap-tests" fails due to test code bug
* [72a87e3](https://github.com/hyperledger/fabric-ca/commit/72a87e3) Enforce validity period in COP for ECerts/TCerts
* [718647e](https://github.com/hyperledger/fabric-ca/commit/718647e) Clean up Config structure
* [35a1f13](https://github.com/hyperledger/fabric-ca/commit/35a1f13) Integrate TCert library into COP server and client
* [923148b](https://github.com/hyperledger/fabric-ca/commit/923148b) Complete step 2 of cop client revoke work
* [6fc7615](https://github.com/hyperledger/fabric-ca/commit/6fc7615) Add support for TLS and config file enhanced
* [c11e7f4](https://github.com/hyperledger/fabric-ca/commit/c11e7f4) More tcert library APIs prior to COP integration
* [bdea0cf](https://github.com/hyperledger/fabric-ca/commit/bdea0cf) [FAB-1470](https://jira.hyperledger.org/browse/FAB-1470) Fix docker-clean Makefile target
* [776c117](https://github.com/hyperledger/fabric-ca/commit/776c117) Add .gitreview
* [8ede0e0](https://github.com/hyperledger/fabric-ca/commit/8ede0e0) Remove duplicated test data
* [f1a894a](https://github.com/hyperledger/fabric-ca/commit/f1a894a) Add command instruction to Makefile
* [4526770](https://github.com/hyperledger/fabric-ca/commit/4526770) Address [FAB-1454](https://jira.hyperledger.org/browse/FAB-1454) add docker image for fabric-cop
* [4bd06ec](https://github.com/hyperledger/fabric-ca/commit/4bd06ec) Adding TCert Library API
* [17abd20](https://github.com/hyperledger/fabric-ca/commit/17abd20) Extend CFSSL accessor to support ID in Cert table
* [5802e29](https://github.com/hyperledger/fabric-ca/commit/5802e29) Add shebang to run_ldap_tests sctipt
* [ed2ad83](https://github.com/hyperledger/fabric-ca/commit/ed2ad83) Crypto Support for TCert
* [a7432e4](https://github.com/hyperledger/fabric-ca/commit/a7432e4) Documentation fix README.md
* [32cba00](https://github.com/hyperledger/fabric-ca/commit/32cba00) Add LDAP support to COP server
* [690c33c](https://github.com/hyperledger/fabric-ca/commit/690c33c) Group Prekey, Serial Number, and Max Enrollments
* [d88fd4a](https://github.com/hyperledger/fabric-ca/commit/d88fd4a) [FAB-1214](https://jira.hyperledger.org/browse/FAB-1214): Generates a fabric-cop image for docker
* [7efaab6](https://github.com/hyperledger/fabric-ca/commit/7efaab6) Abstract DB and enable plugging in LDAP
* [de5918d](https://github.com/hyperledger/fabric-ca/commit/de5918d) Run the COP server in a cluster (MySQL)
* [dccf180](https://github.com/hyperledger/fabric-ca/commit/dccf180) Run the COP server in a cluster (Postgres)
* [ba8ff6e](https://github.com/hyperledger/fabric-ca/commit/ba8ff6e) Vendor BCCSP from FABRIC into FABRIC-COP
* [90bd09f](https://github.com/hyperledger/fabric-ca/commit/90bd09f) Copy/modify cfssl serve.go
* [ffb4fc2](https://github.com/hyperledger/fabric-ca/commit/ffb4fc2) Add support for certificate revocation
* [84328df](https://github.com/hyperledger/fabric-ca/commit/84328df) Add support for cop client reenroll
* [66cd46d](https://github.com/hyperledger/fabric-ca/commit/66cd46d) fix code coverage report issue
* [1114d56](https://github.com/hyperledger/fabric-ca/commit/1114d56) Add database config as part of server config
* [ec34a1d](https://github.com/hyperledger/fabric-ca/commit/ec34a1d) [FAB-449](https://jira.hyperledger.org/browse/FAB-449) with updated README.md: cop server init CSRJSON
* [46ce6be](https://github.com/hyperledger/fabric-ca/commit/46ce6be) Improve COP CLI error messages
* [9ccf04a](https://github.com/hyperledger/fabric-ca/commit/9ccf04a) [FAB-1015](https://jira.hyperledger.org/browse/FAB-1015) code coverage report for fabric-cop repository
* [33fa279](https://github.com/hyperledger/fabric-ca/commit/33fa279) Testcases added to support better test coverage
* [3ef8656](https://github.com/hyperledger/fabric-ca/commit/3ef8656) Added license headers
* [a264a94](https://github.com/hyperledger/fabric-ca/commit/a264a94) Initial COP impl of IDP APIs
* [ffa64c8](https://github.com/hyperledger/fabric-ca/commit/ffa64c8) Add Identity Provider APIs
* [df3844d](https://github.com/hyperledger/fabric-ca/commit/df3844d) Initial COP checkin


<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
s
