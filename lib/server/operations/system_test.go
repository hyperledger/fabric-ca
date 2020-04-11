/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operations_test

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-ca/lib/server/operations"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/hyperledger/fabric/common/metrics/prometheus"
	"github.com/hyperledger/fabric/common/metrics/statsd"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("System", func() {
	var (
		tempDir string

		authClient   *http.Client
		unauthClient *http.Client
		options      operations.Options
		system       *operations.System
	)

	BeforeEach(func() {
		var err error
		tempDir, err = ioutil.TempDir("", "system")
		Expect(err).NotTo(HaveOccurred())

		err = generateCertificates(tempDir)
		Expect(err).NotTo(HaveOccurred())

		options = operations.Options{
			ListenAddress: "127.0.0.1:0",
			Metrics: operations.MetricsOptions{
				Provider: "disabled",
			},
			TLS: operations.TLS{
				Enabled:            true,
				CertFile:           filepath.Join(tempDir, "server-cert.pem"),
				KeyFile:            filepath.Join(tempDir, "server-key.pem"),
				ClientCertRequired: false,
				ClientCACertFiles:  []string{filepath.Join(tempDir, "client-ca.pem")},
			},
		}

		system = operations.NewSystem(options)

		authClient = newHTTPClient(tempDir, true)
		unauthClient = newHTTPClient(tempDir, false)
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
		if system != nil {
			system.Stop()
		}
	})

	It("hosts an unsecured endpoint for the version information", func() {
		err := system.Start()
		Expect(err).NotTo(HaveOccurred())

		versionURL := fmt.Sprintf("https://%s/version", system.Addr())
		resp, err := unauthClient.Get(versionURL)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		resp.Body.Close()
	})

	Context("when ClientCertRequired is true", func() {
		BeforeEach(func() {
			options.TLS.ClientCertRequired = true
			system = operations.NewSystem(options)
		})

		It("requires a client cert to connect", func() {
			err := system.Start()
			Expect(err).NotTo(HaveOccurred())

			_, err = unauthClient.Get(fmt.Sprintf("https://%s/metrics", system.Addr()))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("remote error: tls: bad certificate"))
		})
	})

	Context("when listen fails", func() {
		var listener net.Listener

		BeforeEach(func() {
			var err error
			listener, err = net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())

			options.ListenAddress = listener.Addr().String()
			system = operations.NewSystem(options)
		})

		AfterEach(func() {
			listener.Close()
		})

		It("returns an error", func() {
			err := system.Start()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("bind: address already in use"))
		})
	})

	Context("when a bad TLS configuration is provided", func() {
		BeforeEach(func() {
			options.TLS.CertFile = "cert-file-does-not-exist"
			system = operations.NewSystem(options)
		})

		It("returns an error", func() {
			err := system.Start()
			Expect(err).To(MatchError("open cert-file-does-not-exist: no such file or directory"))
		})
	})

	Context("when the metrics provider is disabled", func() {
		BeforeEach(func() {
			options.Metrics = operations.MetricsOptions{
				Provider: "disabled",
			}
			system = operations.NewSystem(options)
			Expect(system).NotTo(BeNil())
		})

		It("sets up a disabled provider", func() {
			Expect(system.Provider).To(Equal(&disabled.Provider{}))
		})
	})

	Context("when the metrics provider is prometheus", func() {
		BeforeEach(func() {
			options.Metrics = operations.MetricsOptions{
				Provider: "prometheus",
			}
			system = operations.NewSystem(options)
			Expect(system).NotTo(BeNil())
		})

		It("sets up prometheus as a provider", func() {
			Expect(system.Provider).To(Equal(&prometheus.Provider{}))
		})

		It("hosts a secure endpoint for metrics", func() {
			err := system.Start()
			Expect(err).NotTo(HaveOccurred())

			metricsURL := fmt.Sprintf("https://%s/metrics", system.Addr())
			resp, err := authClient.Get(metricsURL)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			Expect(err).NotTo(HaveOccurred())
			Expect(body).To(ContainSubstring("# TYPE go_gc_duration_seconds summary"))
		})
	})

	Context("when the metrics provider is statsd", func() {
		var listener net.Listener

		BeforeEach(func() {
			var err error
			listener, err = net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())

			options.Metrics = operations.MetricsOptions{
				Provider: "statsd",
				Statsd: &operations.Statsd{
					Network:       "tcp",
					Address:       listener.Addr().String(),
					WriteInterval: 100 * time.Millisecond,
					Prefix:        "prefix",
				},
			}
			system = operations.NewSystem(options)
			Expect(system).NotTo(BeNil())
		})

		AfterEach(func() {
			listener.Close()
		})

		It("sets up statsd as a provider", func() {
			provider, ok := system.Provider.(*statsd.Provider)
			Expect(ok).To(BeTrue())
			Expect(provider.Statsd).NotTo(BeNil())
		})

		Context("when checking the network and address fails", func() {
			BeforeEach(func() {
				options.Metrics.Statsd.Network = "bob-the-network"
				system = operations.NewSystem(options)
			})

			It("returns an error", func() {
				err := system.Start()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("bob-the-network"))
			})
		})
	})

	Context("when the metrics provider is unknown", func() {
		BeforeEach(func() {
			options.Metrics.Provider = "something-unknown"
			system = operations.NewSystem(options)
		})

		It("sets up a disabled provider", func() {
			Expect(system.Provider).To(Equal(&disabled.Provider{}))
		})
	})
})
