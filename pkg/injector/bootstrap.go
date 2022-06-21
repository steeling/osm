package injector

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy/bootstrap"
	"github.com/openservicemesh/osm/pkg/utils"
	"github.com/openservicemesh/osm/pkg/version"
)

func (wh *mutatingWebhook) createEnvoyBootstrapConfig(name, namespace, osmNamespace string, cert *certificate.Certificate, originalHealthProbes bootstrap.HealthProbes) (*corev1.Secret, error) {
	builder := bootstrap.Builder{
		Certificate:  cert,
		OSMNamespace: osmNamespace,
		XDSHost:      fmt.Sprintf("%s.%s.svc.cluster.local", constants.OSMControllerName, osmNamespace),

		// OriginalHealthProbes stores the path and port for liveness, readiness, and startup health probes as initially
		// defined on the Pod Spec.
		OriginalHealthProbes: originalHealthProbes,

		TLSMinProtocolVersion: wh.configurator.GetMeshConfig().Spec.Sidecar.TLSMinProtocolVersion,
		TLSMaxProtocolVersion: wh.configurator.GetMeshConfig().Spec.Sidecar.TLSMaxProtocolVersion,
		CipherSuites:          wh.configurator.GetMeshConfig().Spec.Sidecar.CipherSuites,
		ECDHCurves:            wh.configurator.GetMeshConfig().Spec.Sidecar.ECDHCurves,
	}

	existing, err := wh.kubeClient.CoreV1().Secrets(namespace).Get(context.Background(), oldBootstrapSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	yamlBytes := existing.Data[bootstrap.EnvoyBootstrapConfigFile]

	config := &xds_bootstrap.Bootstrap{}
	if err := utils.YAMLToProto(yamlBytes, config); err != nil {
		return nil, fmt.Errorf("error unmarshalling envoy bootstrap config: %w", err)
	}

	config, err := builder.Build()
	if err != nil {
		return nil, err
	}

	tlsYamlContent, err := bootstrap.GetTLSSDSConfigYAML()
	if err != nil {
		log.Error().Err(err).Msg("Error creating Envoy TLS Certificate SDS Config YAML")
		return nil, err
	}

	validationYamlContent, err := bootstrap.GetValidationContextSDSConfigYAML()
	if err != nil {
		log.Error().Err(err).Msg("Error creating Envoy Validation Context SDS Config YAML")
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				constants.OSMAppNameLabelKey:     constants.OSMAppNameLabelValue,
				constants.OSMAppInstanceLabelKey: wh.meshName,
				constants.OSMAppVersionLabelKey:  version.Version,
			},
		},
		Data: map[string][]byte{
			bootstrap.EnvoyBootstrapConfigFile:            config,
			bootstrap.EnvoyTLSCertificateSDSSecretFile:    tlsYamlContent,
			bootstrap.EnvoyValidationContextSDSSecretFile: validationYamlContent,
			bootstrap.EnvoyXDSCACertFile:                  cert.GetTrustedCAs(),
			bootstrap.EnvoyXDSCertFile:                    cert.GetCertificateChain(),
			bootstrap.EnvoyXDSKeyFile:                     cert.GetPrivateKey(),
		},
	}

	log.Debug().Msgf("Creating bootstrap config for Envoy: name=%s, namespace=%s", name, namespace)
	return wh.kubeClient.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
}
