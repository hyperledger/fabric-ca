# Simple load driver for Fabric CA
This is a simple load driver for Fabric CA. The driver can be configured using a JSON configuration file. Things like URL of the Fabric CA server, number of clients, number of requests per client, requests per second, test sequence, Fabric CA Client config, etc can be specified in the configuration file. You can look at the default configuraton file **testConfig.yml** located in this directory.

## Steps
1. Set `registry.maxEnrollments` to at least 2 in the server configuration file
1. Make sure Fabric CA server is running and make a note of the server URL, bootstrap user and password.
2. Modify the **testConfig.yml** file
    * Modify the `serverURL` property. It is of the form: `<http|https>://<bootstrap user id>:<bootstrap password>@<hostname>:<port>`. Note that the bootstrap user must have revoker authority and must be affiliated with root of the affiliation tree, which is **""** or the parent affiliation of the affiliation specified in the `affiliation` property
    * Change load properties like `numClients`, `numReqsPerClient`, `testSeq` properties as needed. `testSeq` property specifies the sequence of tests that are run in each iteration by a client. Each test has a `name` and optional `repeat` and `req` properties. The `repeat` property specifies how many times to repeat the test in each iteration. The `req` property specifies payload for the request that is sent to the Fabric CA server.
        * For revoke test, specify a random string for the `name` property if you need to revoke an identity. If the `name` property is empty, an ECert associated with the identity will be revoked.
    * Change `affiliation` property. It specifies the affiliation to use in the test.
    * If you need TLS to be used to connect to the Fabric CA server, first make sure **https** protocol is used in the `serverURL` property. Next, set `tls.enabled` to true. Then, specify root CA certificate files in the `tls.certfiles` property.
3. Run **runLoad.sh** script to start the load test. You can invoke this script with the `-B` option to build the driver and run.
