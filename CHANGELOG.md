## v1.0.6
Sun Feb 18 11:48:51 EST 2018

* [4816994](https://github.com/hyperledger/fabric-ca/commit/4816994) [FAB-7596](https://jira.hyperledger.org/browse/FAB-7596) Modify enroll cmd to read env var
* [cd93c3c](https://github.com/hyperledger/fabric-ca/commit/cd93c3c) [FAB-7489](https://jira.hyperledger.org/browse/FAB-7489) TLS test certs are expired
* [da11ecb](https://github.com/hyperledger/fabric-ca/commit/da11ecb) [FAB-7285](https://jira.hyperledger.org/browse/FAB-7285) Prepare fabric-ca for v1.0.6 release

## v1.0.5
Wed Dec  6 11:37:49 WET 2017

* [1cb0c8c](https://github.com/hyperledger/fabric-ca/commit/1cb0c8c) [FAB-6991](https://jira.hyperledger.org/browse/FAB-6991) Fix max enrollments for bootstrap user
* [048c434](https://github.com/hyperledger/fabric-ca/commit/048c434) [FAB-7055](https://jira.hyperledger.org/browse/FAB-7055) Backport [FAB-5786] to release
* [26110c0](https://github.com/hyperledger/fabric-ca/commit/26110c0) [FAB-6796](https://jira.hyperledger.org/browse/FAB-6796) Prepare fabric-ca for v1.0.5 development

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
