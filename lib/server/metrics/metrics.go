/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import "github.com/hyperledger/fabric/common/metrics"

var (
	// APICounterOpts define the counter opts for server APIs
	APICounterOpts = metrics.CounterOpts{
		Namespace:  "api_request",
		Subsystem:  "",
		Name:       "count",
		Help:       "Number of requests made to an API",
		LabelNames: []string{"ca_name", "api_name", "status_code"},
		LabelHelp: map[string]string{
			"api_name":    "example api_names: affiliations/{affiliation}, affiliations, certificates, enroll, reenroll, gencrl, idemix/cri, identities, register, revoke, idemix/credential, identities/{id}. ",
			"status_code": "Http status code. https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html",
		},
		StatsdFormat: "%{#fqname}.%{ca_name}.%{api_name}.%{status_code}",
	}

	// APIDurationOpts define the duration opts for server APIs
	APIDurationOpts = metrics.HistogramOpts{
		Namespace:  "api_request",
		Subsystem:  "",
		Name:       "duration",
		Help:       "Time taken in seconds for the request to an API to be completed",
		LabelNames: []string{"ca_name", "api_name", "status_code"},
		LabelHelp: map[string]string{
			"api_name":    "example api_names: affiliations/{affiliation}, affiliations, certificates, enroll, reenroll, gencrl, idemix/cri, identities, register, revoke, idemix/credential, identities/{id}. ",
			"status_code": "Http status code. https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html",
		},
		StatsdFormat: "%{#fqname}.%{ca_name}.%{api_name}.%{status_code}",
	}
)

// Metrics are the metrics tracked by server
type Metrics struct {
	// APICounter keeps track of number of times an API endpoint is called
	APICounter metrics.Counter
	// APIDuration keeps track of time taken for request to complete for an API
	APIDuration metrics.Histogram
}
