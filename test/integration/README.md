## Integration Testing

This document describes the integration test package file and code layout strategy.

#### Goal

The goal of this package is to run end-to-end test between the Fabric CA client and server.
Each test should ideally execute fabric-ca-client commands that will execute a specific function
on the server.

#### File Naming Convention
Each test file should contain tests that are per-server configuration. In default_test.go, a
default server configuration is laid out and most default options are used. This file should
contain all tests that are tested against a default server. If tests need to be run against a
server that uses other configuration options, a new test file should be created and within this
file, a new server configuration should be defined.

#### Coding Convention
Tests should be written so as to minimize the starting and stopping of the server, this is the
recommended approach to help minimize test runtime. The use of TestMain can be utilized to prevent
multiple starts and stops.

This assumes that each test is a unit and doesn't change the state of the server in a way that matters
or would affect the running of another test also in this file. If tests are related and order dependent,
then a single TestXXX could call multiple testYYY functions in a definite order.
