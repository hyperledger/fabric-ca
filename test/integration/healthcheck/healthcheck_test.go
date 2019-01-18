/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package healthcheck

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-lib-go/healthz"

	"github.com/stretchr/testify/assert"
)

func TestHealthCheckEndpoint(t *testing.T) {
	server := lib.TestGetRootServer(t)
	server.Config.Operations.ListenAddress = "127.0.0.1:0"

	err := server.Start()
	assert.NoError(t, err)
	defer server.Stop()
	defer os.RemoveAll("rootDir")

	_, port, err := net.SplitHostPort(server.Operations.Addr())
	assert.NoError(t, err)

	client := &http.Client{}
	healthURL := fmt.Sprintf("http://127.0.0.1:%s/healthz", port)

	resp, err := client.Get(healthURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = server.GetDB().Close()
	assert.NoError(t, err)

	resp, err = client.Get(healthURL)
	assert.NoError(t, err)

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)

	resp.Body.Close()

	var healthStatus healthz.HealthStatus
	err = json.Unmarshal(bodyBytes, &healthStatus)
	assert.NoError(t, err)

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "server", healthStatus.FailedChecks[0].Component)
	assert.Equal(t, "sql: database is closed", healthStatus.FailedChecks[0].Reason)
}
