package bootstrap

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test functions creating Envoy bootstrap configuration", func() {

	It("Creates Envoy bootstrap config for the Envoy proxy", func() {

		mockCtrl := gomock.NewController(GinkgoT())
		mockConfigurator := configurator.NewMockConfigurator(mockCtrl)
		mockConfigurator.EXPECT().GetMeshConfig().Return(meshConfig).AnyTimes()

		wh := &mutatingWebhook{
			kubeClient:          fake.NewSimpleClientset(),
			kubeController:      k8s.NewMockController(gomock.NewController(GinkgoT())),
			nonInjectNamespaces: mapset.NewSet(),
			meshName:            "some-mesh",
			configurator:        mockConfigurator,
		}
		name := uuid.New().String()
		namespace := "a"
		osmNamespace := "b"

		getExpectedEnvoyYAML := func(filename string) string {
			expectedEnvoyConfig, err := ioutil.ReadFile(filepath.Clean(path.Join(directoryForYAMLFiles, filename)))
			if err != nil {
				log.Error().Err(err).Msgf("Error reading expected Envoy bootstrap YAML from file %s", filename)
			}
			Expect(err).ToNot(HaveOccurred())
			return string(expectedEnvoyConfig)
		}

		secret, err := wh.createEnvoyBootstrapConfig(name, namespace, osmNamespace, cert, probes)
		Expect(err).ToNot(HaveOccurred())

		expected := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels: map[string]string{
					constants.OSMAppNameLabelKey:     constants.OSMAppNameLabelValue,
					constants.OSMAppInstanceLabelKey: "some-mesh",
					constants.OSMAppVersionLabelKey:  version.Version,
				},
			},
			Data: map[string][]byte{
				bootstrap.EnvoyBootstrapConfigFile:            []byte(getExpectedEnvoyYAML(expectedEnvoyBootstrapConfigFileName)),
				bootstrap.EnvoyTLSCertificateSDSSecretFile:    []byte(getExpectedEnvoyYAML(expectedEnvoyTLSCertificateSDSSecretFileName)),
				bootstrap.EnvoyValidationContextSDSSecretFile: []byte(getExpectedEnvoyYAML(expectedEnvoyValidationContextSDSSecretFileName)),
				bootstrap.EnvoyXDSCACertFile:                  cert.IssuingCA,
				bootstrap.EnvoyXDSCertFile:                    cert.CertChain,
				bootstrap.EnvoyXDSKeyFile:                     cert.PrivateKey,
			},
		}

		// Contains the following keys:
		// - "bootstrap.yaml"
		// - "tls_certificate_sds_secret.yaml"
		// - "validation_context_sds_secret.yaml"
		// - "ca_cert.pem"
		// - "sds_cert.pem"
		// - "sds_key.pem"
		Expect(len(secret.Data)).To(Equal(6))

		Expect(secret.Data[bootstrap.EnvoyBootstrapConfigFile]).To(Equal(secret.Data[bootstrap.EnvoyBootstrapConfigFile]),
			fmt.Sprintf("Expected YAML: %s;\nActual YAML: %s\n", expected.Data, secret.Data))

		Expect(secret.Data[bootstrap.EnvoyTLSCertificateSDSSecretFile]).To(Equal(secret.Data[bootstrap.EnvoyTLSCertificateSDSSecretFile]),
			fmt.Sprintf("Expected YAML: %s;\nActual YAML: %s\n", expected.Data, secret.Data))

		Expect(secret.Data[bootstrap.EnvoyValidationContextSDSSecretFile]).To(Equal(secret.Data[bootstrap.EnvoyValidationContextSDSSecretFile]),
			fmt.Sprintf("Expected YAML: %s;\nActual YAML: %s\n", expected.Data, secret.Data))

		Expect(secret.Data[bootstrap.EnvoyXDSCACertFile]).To(Equal(expected.Data[bootstrap.EnvoyXDSCACertFile]),
			fmt.Sprintf("Expected YAML: %s;\nActual YAML: %s\n", expected.Data, secret.Data))

		Expect(secret.Data[bootstrap.EnvoyXDSCertFile]).To(Equal(expected.Data[bootstrap.EnvoyXDSCertFile]),
			fmt.Sprintf("Expected YAML: %s;\nActual YAML: %s\n", expected.Data, secret.Data))

		Expect(secret.Data[bootstrap.EnvoyXDSKeyFile]).To(Equal(expected.Data[bootstrap.EnvoyXDSKeyFile]),
			fmt.Sprintf("Expected YAML: %s;\nActual YAML: %s\n", expected.Data, secret.Data))

		// Now check the entire struct
		Expect(*secret).To(Equal(expected))
	})
})
