package providers

import (
	"context"
	"fmt"
	"time"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversionedclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/certificate/providers/certmanager"
	"github.com/openservicemesh/osm/pkg/certificate/providers/tresor"
	"github.com/openservicemesh/osm/pkg/certificate/providers/vault"
	"github.com/openservicemesh/osm/pkg/certificate/rotor"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/version"
)

const (
	checkCertificateExpirationInterval = 5 * time.Second
	// Additional values for the root certificate
	rootCertCountry      = "US"
	rootCertLocality     = "CA"
	rootCertOrganization = "Open Service Mesh"
)

// NewCertificateProvider returns a new certificate provider and associated config
func NewCertificateProvider(kubeClient kubernetes.Interface, kubeConfig *rest.Config,
	providerNamespace string, caBundleSecretName string, msgBroker *messaging.Broker, options Options) (cm certificate.Manager, err error) {
	// config := &Config{
	// 	kubeClient:         kubeClient,
	// 	kubeConfig:         kubeConfig,
	// 	cfg:                cfg,
	// 	providerKind:       providerKind,
	// 	providerNamespace:  providerNamespace,
	// 	caBundleSecretName: caBundleSecretName,

	// 	tresorOptions:      tresorOptions,
	// 	vaultOptions:       vaultOptions,
	// 	certManagerOptions: certManagerOptions,

	// 	msgBroker: msgBroker,
	// }
	defer func() {
		if cm != nil {
			// Instantiating a new certificate rotation mechanism will start a goroutine for certificate rotation.
			rotor.New(cm).Start(checkCertificateExpirationInterval)
		}
	}()
	switch v := options.(type) {
	case tresor.Options:
		return getTresorOSMCertificateManager(v)
	case vault.Options:
		return vault.NewCertManager(v)
	case certmanager.Options:
		return getCertManagerOSMCertificateManager(v)
	default:
		return nil, fmt.Errorf("Unsupported Certificate Manager options: %++v", options)
	}
}

// GetOrCreateCertificateFromSecret is a helper function that ensures creation and synchronization of a certificate
// using Kubernetes Secrets backend and API atomicity.
func GetOrCreateCertificateFromSecret(ns string, secretName string, cert certificate.Certificater, kubeClient kubernetes.Interface) (certificate.Certificater, error) {
	// Attempt to create it in Kubernetes. When multiple agents attempt to create, only one of them will succeed.
	// All others will get "AlreadyExists" error back.
	secretData := map[string][]byte{
		constants.KubernetesOpaqueSecretCAKey:             cert.GetCertificateChain(),
		constants.KubernetesOpaqueSecretRootPrivateKeyKey: cert.GetPrivateKey(),
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels: map[string]string{
				constants.OSMAppNameLabelKey:    constants.OSMAppNameLabelValue,
				constants.OSMAppVersionLabelKey: version.Version,
			},
		},
		Data: secretData,
	}

	if _, err := kubeClient.CoreV1().Secrets(ns).Create(context.TODO(), secret, metav1.CreateOptions{}); err == nil {
		log.Info().Msgf("Secret %s/%s created in kubernetes", ns, secretName)
	} else if apierrors.IsAlreadyExists(err) {
		log.Info().Msgf("Secret %s/%s already exists in kubernetes, loading.", ns, secretName)
	} else {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrCreatingCertSecret)).
			Msgf("Error creating/retrieving certificate secret %s/%s", ns, secretName)
		return nil, err
	}

	// For simplicity, we will load the certificate for all of them, this way the instance which created it
	// and the ones that didn't share the same code.
	cert, err := GetCertFromKubernetes(ns, secretName, kubeClient)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch certificate from Kubernetes")
		return nil, err
	}

	return cert, nil
}

// getTresorOSMCertificateManager returns a certificate manager instance with Tresor as the certificate provider
func getTresorOSMCertificateManager(opts tresor.Options) (certificate.Manager, error) {
	var err error
	var rootCert certificate.Certificater

	// This part synchronizes CA creation using the inherent atomicity of kubernetes API backend
	// Assuming multiple instances of Tresor are instantiated at the same time, only one of them will
	// succeed to issue a "Create" of the secret. All other Creates will fail with "AlreadyExists".
	// Regardless of success or failure, all instances can proceed to load the same CA.

	rootCert, err = tresor.NewCA(constants.CertificationAuthorityCommonName, constants.CertificationAuthorityRootValidityPeriod, rootCertCountry, rootCertLocality, rootCertOrganization)

	if err != nil {
		return nil, errors.Errorf("Failed to create new Certificate Authority with cert issuer tresor")
	}

	if rootCert == nil {
		return nil, errors.Errorf("Invalid root certificate created by cert issuer tresor")
	}

	if rootCert.GetPrivateKey() == nil {
		return nil, errors.Errorf("Root cert does not have a private key")
	}

	rootCert, err = GetOrCreateCertificateFromSecret(opts.providerNamespace, c.caBundleSecretName, rootCert, c.kubeClient)
	if err != nil {
		return nil, errors.Errorf("Failed to synchronize certificate on Secrets API : %v", err)
	}

	opts.CertificatesOrganization = rootCertOrganization
	opts.CA = rootCert
	return tresor.NewCertManager(opts), nil
}

// GetCertFromKubernetes is a helper function that loads a certificate from a Kubernetes secret
// The function returns an error only if a secret is found with invalid data.
func GetCertFromKubernetes(ns string, secretName string, kubeClient kubernetes.Interface) (certificate.Certificater, error) {
	certSecret, err := kubeClient.CoreV1().Secrets(ns).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrFetchingCertSecret)).
			Msgf("Could not retrieve certificate secret %q from namespace %q", secretName, ns)
		return nil, errSecretNotFound
	}

	pemCert, ok := certSecret.Data[constants.KubernetesOpaqueSecretCAKey]
	if !ok {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Err(errInvalidCertSecret).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrObtainingCertFromSecret)).
			Msgf("Opaque k8s secret %s/%s does not have required field %q", ns, secretName, constants.KubernetesOpaqueSecretCAKey)
		return nil, errInvalidCertSecret
	}

	pemKey, ok := certSecret.Data[constants.KubernetesOpaqueSecretRootPrivateKeyKey]
	if !ok {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Err(errInvalidCertSecret).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrObtainingPrivateKeyFromSecret)).
			Msgf("Opaque k8s secret %s/%s does not have required field %q", ns, secretName, constants.KubernetesOpaqueSecretRootPrivateKeyKey)
		return nil, errInvalidCertSecret
	}

	cert, err := tresor.NewCertificateFromPEM(pemCert, pemKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create new Certificate from PEM")
		return nil, err
	}

	return cert, nil
}

// getCertManagerOSMCertificateManager returns a certificate manager instance with cert-manager as the certificate provider
func getCertManagerOSMCertificateManager(kubeClient, providerNamespace, caBundleSecretName string, options certmanager.Options) (certificate.Manager, error) {
	rootCertSecret, err := kubeClient.CoreV1().Secrets(c.providerNamespace).Get(context.TODO(), c.caBundleSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to get cert-manager CA secret %s/%s: %s", c.providerNamespace, c.caBundleSecretName, err)
	}

	pemCert, ok := rootCertSecret.Data[constants.KubernetesOpaqueSecretCAKey]
	if !ok {
		return nil, fmt.Errorf("Opaque k8s secret %s/%s does not have required field %q", providerNamespace, caBundleSecretName, constants.KubernetesOpaqueSecretCAKey)
	}

	rootCert, err := certmanager.NewRootCertificateFromPEM(pemCert)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode cert-manager CA certificate from secret %s/%s: %s", providerNamespace, caBundleSecretName, err)
	}

	client, err := cmversionedclient.NewForConfig(c.kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to build cert-manager client set: %s", err)
	}

	certmanagerCertManager, err := certmanager.NewCertManager(
		rootCert,
		client,
		c.providerNamespace,
		cmmeta.ObjectReference{
			Name:  options.IssuerName,
			Kind:  options.IssuerKind,
			Group: options.IssuerGroup,
		},
	)
	if err != nil {
		return nil, errors.Errorf("Error instantiating Jetstack cert-manager as a Certificate Manager: %+v", err)
	}

	return certmanagerCertManager, nil
}
