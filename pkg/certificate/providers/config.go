package providers

import (
	"context"
	"fmt"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversionedclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/certificate/castorage/k8s"
	"github.com/openservicemesh/osm/pkg/certificate/providers/certmanager"
	"github.com/openservicemesh/osm/pkg/certificate/providers/tresor"
	"github.com/openservicemesh/osm/pkg/certificate/providers/vault"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/debugger"
	"github.com/openservicemesh/osm/pkg/messaging"
)

const (
	// Additional values for the root certificate
	rootCertCountry      = "US"
	rootCertLocality     = "CA"
	rootCertOrganization = "Open Service Mesh"
)

// GenerateCertificateManager returns a new certificate manager and associated config
// TODO: remove this function once we have a new certificate.Manager implementation that accepts a certificate.MRCClient
// and a MRCProviderGenerator, that are created separately.
func GenerateCertificateManager(kubeClient kubernetes.Interface, kubeConfig *rest.Config, cfg configurator.Configurator,
	providerNamespace string, options Options, msgBroker *messaging.Broker) (*certificate.Manager, debugger.CertificateManagerDebugger, error) {
	legacyClient, err := NewMRCCompatClient(cfg, providerNamespace, options)
	if err != nil {
		return nil, nil, err
	}

	mrc := legacyClient.mrc

	generator := &MRCProviderGenerator{
		kubeClient:                  kubeClient,
		kubeConfig:                  kubeConfig,
		msgBroker:                   msgBroker,
		ServiceCertValidityDuration: cfg.GetServiceCertValidityPeriod(),
		KeyBitSize:                  cfg.GetCertKeyBitSize(),
	}

	certManager, certDebugger, err := generator.GetProviderForMRC(mrc)
	if err != nil {
		return nil, nil, err
	}

	return certManager, certDebugger, nil
}

// GetProviderForMRC currently returns a full blown certificate.Manager.
// TODO(#4502): This method should return a certificate.Provider interface, it has only been separated to keep the
// PR smaller and readable; there are no blockers for the next PR.
func (c *MRCProviderGenerator) GetProviderForMRC(mrc *v1alpha2.MeshRootCertificate) (*certificate.Manager, debugger.CertificateManagerDebugger, error) {
	p := mrc.Spec.Provider
	switch {
	case p.Tresor != nil:
		return c.getTresorOSMCertificateManager(mrc)
	case p.Vault != nil:
		return c.getHashiVaultOSMCertificateManager(mrc)
	case p.CertManager != nil:
		return c.getCertManagerOSMCertificateManager(mrc)
	default:
		return nil, nil, fmt.Errorf("Unknown certificate provider: %+v", p)
	}
}

// getTresorOSMCertificateManager returns a certificate manager instance with Tresor as the certificate provider
func (c *MRCProviderGenerator) getTresorOSMCertificateManager(mrc *v1alpha2.MeshRootCertificate) (*certificate.Manager, debugger.CertificateManagerDebugger, error) {
	var err error
	var rootCert *certificate.Certificate

	// This part synchronizes CA creation using the inherent atomicity of kubernetes API backend
	// Assuming multiple instances of Tresor are instantiated at the same time, only one of them will
	// succeed to issue a "Create" of the secret. All other Creates will fail with "AlreadyExists".
	// Regardless of success or failure, all instances can proceed to load the same CA.

	rootCert, err = tresor.NewCA(constants.CertificationAuthorityCommonName, constants.CertificationAuthorityRootValidityPeriod, rootCertCountry, rootCertLocality, rootCertOrganization)

	if err != nil {
		return nil, nil, errors.New("Failed to create new Certificate Authority with cert issuer tresor")
	}

	if rootCert == nil {
		return nil, nil, errors.New("Invalid root certificate created by cert issuer tresor")
	}

	if rootCert.GetPrivateKey() == nil {
		return nil, nil, errors.New("Root cert does not have a private key")
	}

	rootCert, err = k8s.GetCertificateFromSecret(mrc.Namespace, mrc.Spec.Provider.Tresor.SecretName, rootCert, c.kubeClient)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to synchronize certificate on Secrets API : %w", err)
	}

	if rootCert.GetPrivateKey() == nil {
		return nil, nil, fmt.Errorf("Root cert does not have a private key: %w", certificate.ErrInvalidCertSecret)
	}

	tresorClient, err := tresor.New(
		rootCert,
		rootCertOrganization,
		c.KeyBitSize,
	)
	if err != nil {
		return nil, nil, errors.New("Failed to instantiate Tresor as a Certificate Manager")
	}

	tresorCertManager, err := certificate.NewManager(rootCert, tresorClient, c.ServiceCertValidityDuration, c.msgBroker)
	if err != nil {
		return nil, nil, fmt.Errorf("error instantiating osm certificate.Manager for Tresor cert-manager : %w", err)
	}
	return tresorCertManager, tresorCertManager, nil
}

// getHashiVaultOSMCertificateManager returns a certificate manager instance with Hashi Vault as the certificate provider
func (c *MRCProviderGenerator) getHashiVaultOSMCertificateManager(mrc *v1alpha2.MeshRootCertificate) (*certificate.Manager, debugger.CertificateManagerDebugger, error) {
	provider := mrc.Spec.Provider.Vault
	if _, ok := map[string]interface{}{"http": nil, "https": nil}[provider.Protocol]; !ok {
		return nil, nil, fmt.Errorf("value %s is not a valid Hashi Vault protocol", provider.Protocol)
	}

	// A Vault address would have the following shape: "http://vault.default.svc.cluster.local:8200"
	vaultAddr := fmt.Sprintf("%s://%s:%d", provider.Protocol, provider.Host, provider.Port)
	vaultClient, err := vault.New(
		vaultAddr,
		provider.Token,
		provider.Role,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error instantiating Hashicorp Vault as a Certificate Manager: %w", err)
	}

	vaultCert, err := vaultClient.GetRootCertificate()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting Vault Root Certificate, got: %w", err)
	}

	certManager, err := certificate.NewManager(vaultCert, vaultClient, c.ServiceCertValidityDuration, c.msgBroker)
	if err != nil {
		return nil, nil, fmt.Errorf("error instantiating osm certificate.Manager for Vault cert-manager : %w", err)
	}
	return certManager, certManager, nil
}

// getCertManagerOSMCertificateManager returns a certificate manager instance with cert-manager as the certificate provider
func (c *MRCProviderGenerator) getCertManagerOSMCertificateManager(mrc *v1alpha2.MeshRootCertificate) (*certificate.Manager, debugger.CertificateManagerDebugger, error) {
	provider := mrc.Spec.Provider.CertManager
	rootCertSecret, err := c.kubeClient.CoreV1().Secrets(mrc.Namespace).Get(context.TODO(), provider.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get cert-manager CA secret %s/%s: %s", mrc.Namespace, provider.SecretName, err)
	}

	pemCert, ok := rootCertSecret.Data[constants.KubernetesOpaqueSecretCAKey]
	if !ok {
		return nil, nil, fmt.Errorf("Opaque k8s secret %s/%s does not have required field %q", mrc.Namespace, provider.SecretName, constants.KubernetesOpaqueSecretCAKey)
	}

	rootCert, err := certificate.NewFromPEM(pemCert, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to decode cert-manager CA certificate from secret %s/%s: %s", mrc.Namespace, provider.SecretName, err)
	}

	client, err := cmversionedclient.NewForConfig(c.kubeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to build cert-manager client set: %s", err)
	}

	cmClient, err := certmanager.New(
		rootCert,
		client,
		mrc.Namespace,
		cmmeta.ObjectReference{
			Name:  provider.IssuerName,
			Kind:  provider.IssuerKind,
			Group: provider.IssuerGroup,
		},
		c.KeyBitSize,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("Error instantiating Jetstack cert-manager client: %w", err)
	}

	certManager, err := certificate.NewManager(rootCert, cmClient, c.ServiceCertValidityDuration, c.msgBroker)
	if err != nil {
		return nil, nil, fmt.Errorf("error instantiating osm certificate.Manager for Jetstack cert-manager : %w", err)
	}
	return certManager, certManager, nil
}
