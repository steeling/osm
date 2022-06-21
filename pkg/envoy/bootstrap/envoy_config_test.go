package bootstrap

import (
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"

	xds_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/golang/mock/gomock"

	"github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/utils"
)

var _ = Describe("Test functions creating Envoy bootstrap configuration", func() {
	const (
		containerName = "-container-name-"
		envoyImage    = "-envoy-image-"
		clusterID     = "-cluster-id-"

		// This file contains the Bootstrap YAML generated for all of the Envoy proxies in OSM.
		// This is provisioned by the MutatingWebhook during the addition of a sidecar
		// to every new Pod that is being created in a namespace participating in the service mesh.
		// We deliberately leave this entire string literal here to document and visualize what the
		// generated YAML looks like!
		expectedEnvoyBootstrapConfigFileName            = "expected_envoy_bootstrap_config.yaml"
		actualGeneratedEnvoyBootstrapConfigFileName     = "actual_envoy_bootstrap_config.yaml"
		expectedEnvoyTLSCertificateSDSSecretFileName    = "expected_tls_certificate_sds_secret.yaml" // #nosec G101: Potential hardcoded credentials
		expectedEnvoyValidationContextSDSSecretFileName = "expected_validation_context_sds_secret.yaml"

		// All the YAML files listed above are in this sub-directory
		directoryForYAMLFiles = "test_fixtures"
	)

	meshConfig := v1alpha2.MeshConfig{
		Spec: v1alpha2.MeshConfigSpec{
			Sidecar: v1alpha2.SidecarSpec{
				TLSMinProtocolVersion: "TLSv1_2",
				TLSMaxProtocolVersion: "TLSv1_3",
				CipherSuites:          []string{},
			},
		},
	}

	mockCtrl := gomock.NewController(GinkgoT())
	mockConfigurator := configurator.NewMockConfigurator(mockCtrl)
	mockConfigurator.EXPECT().GetMeshConfig().Return(meshConfig).AnyTimes()

	getExpectedEnvoyYAML := func(filename string) string {
		expectedEnvoyConfig, err := ioutil.ReadFile(filepath.Clean(path.Join(directoryForYAMLFiles, filename)))
		if err != nil {
			log.Error().Err(err).Msgf("Error reading expected Envoy bootstrap YAML from file %s", filename)
		}
		Expect(err).ToNot(HaveOccurred())
		return string(expectedEnvoyConfig)
	}

	getExpectedEnvoyConfig := func(filename string) *xds_bootstrap.Bootstrap {
		yaml := getExpectedEnvoyYAML(filename)
		conf := xds_bootstrap.Bootstrap{}
		err := utils.YAMLToProto([]byte(yaml), &conf)
		Expect(err).ToNot(HaveOccurred())
		return &conf
	}

	saveActualEnvoyConfig := func(filename string, actual []byte) {
		err := ioutil.WriteFile(filepath.Clean(path.Join(directoryForYAMLFiles, filename)), actual, 0600)
		if err != nil {
			log.Error().Err(err).Msgf("Error writing actual Envoy Cluster XDS YAML to file %s", filename)
		}
		Expect(err).ToNot(HaveOccurred())
	}

	probes := HealthProbes{
		Liveness:  &HealthProbe{path: "/liveness", port: 81, isHTTP: true},
		Readiness: &HealthProbe{path: "/readiness", port: 82, isHTTP: true},
		Startup:   &HealthProbe{path: "/startup", port: 83, isHTTP: true},
	}

	builder := Builder{
		XDSHost: "osm-controller.b.svc.cluster.local",

		OriginalHealthProbes:  probes,
		TLSMinProtocolVersion: meshConfig.Spec.Sidecar.TLSMinProtocolVersion,
		TLSMaxProtocolVersion: meshConfig.Spec.Sidecar.TLSMaxProtocolVersion,
		CipherSuites:          meshConfig.Spec.Sidecar.CipherSuites,
		ECDHCurves:            meshConfig.Spec.Sidecar.ECDHCurves,
	}

	Context("Test generateEnvoyConfig()", func() {
		It("creates Envoy bootstrap config", func() {
			builder.OriginalHealthProbes = probes
			actual, err := builder.Build()
			Expect(err).ToNot(HaveOccurred())
			saveActualEnvoyConfig(actualGeneratedEnvoyBootstrapConfigFileName, actual)

			expectedEnvoyConfig := getExpectedEnvoyConfig(expectedEnvoyBootstrapConfigFileName)

			expectedYaml, err := utils.ProtoToYAML(expectedEnvoyConfig)
			Expect(err).ToNot(HaveOccurred())

			Expect(actual).To(Equal(expectedYaml),
				fmt.Sprintf("	 %s and %s\nExpected:\n%s\nActual:\n%s\n",
					expectedEnvoyBootstrapConfigFileName, actualGeneratedEnvoyBootstrapConfigFileName, expectedYaml, actual))
		})
	})

	Context("Test getProbeResources()", func() {
		It("Should not create listeners and clusters when there are no probes", func() {
			builder.OriginalHealthProbes = HealthProbes{} // no probes
			actualListeners, actualClusters, err := builder.getProbeResources()
			Expect(err).To(BeNil())
			Expect(actualListeners).To(BeNil())
			Expect(actualClusters).To(BeNil())
		})

		It("Should not create listeners and cluster for TCPSocket probes", func() {
			builder.OriginalHealthProbes = HealthProbes{
				Liveness:  &HealthProbe{port: 81, isTCPSocket: true},
				Readiness: &HealthProbe{port: 82, isTCPSocket: true},
				Startup:   &HealthProbe{port: 83, isTCPSocket: true},
			}
			actualListeners, actualClusters, err := builder.getProbeResources()
			Expect(err).To(BeNil())
			Expect(actualListeners).To(BeNil())
			Expect(actualClusters).To(BeNil())
		})
	})
})
