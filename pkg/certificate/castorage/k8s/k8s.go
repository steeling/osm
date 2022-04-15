package k8s

import (
	"context"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/kubernetes"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/version"
)

var (
	ErrInvalidCertSecret = errors.New("Invalid secret for certificate")
	ErrSecretNotFound    = errors.New("Secret not found")
)

type K8sSecretClient struct {
	kubeClient kubernetes.Interface

	version    string
	secretName string
	namespace  string
}

func (c *K8sSecretClient) Set(ctx context.Context, cert *certificate.Certificate) (string, error) {
	// Attempt to create it in Kubernetes. When multiple agents attempt to create, only one of them will succeed.
	// All others will get "AlreadyExists" error back.
	secretData := map[string][]byte{
		constants.KubernetesOpaqueSecretCAKey: cert.GetCertificateChain(),
	}

	if cert.GetPrivateKey() != nil {
		secretData[constants.KubernetesOpaqueSecretRootPrivateKeyKey] = cert.GetPrivateKey()
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.secretName,
			Namespace: c.namespace,
			Labels: map[string]string{
				constants.OSMAppNameLabelKey:    constants.OSMAppNameLabelValue,
				constants.OSMAppVersionLabelKey: version.Version,
			},
		},
		Data: secretData,
	}

	_, err := c.kubeClient.CoreV1().Secrets(c.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrCreatingCertSecret)).
			Msgf("Error creating/retrieving certificate secret %s/%s", c.namespace, c.secretName)
		return "", err
	}
	log.Info().Msgf("Secret %s/%s created in kubernetes", c.namespace, c.secretName)
	return c.version, nil
}

// GetCertFromKubernetes is a helper function that loads a certificate from a Kubernetes secret
func (c *K8sSecretClient) Get(ctx context.Context) (*certificate.Certificate, error) {
	certSecret, err := c.kubeClient.CoreV1().Secrets(c.namespace).Get(ctx, c.secretName, metav1.GetOptions{})
	if err != nil {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrFetchingCertSecret)).
			Msgf("Could not retrieve certificate secret %q from namespace %q", c.secretName, c.namespace)
		return nil, ErrInvalidCertSecret
	}

	pemCert, ok := certSecret.Data[constants.KubernetesOpaqueSecretCAKey]
	if !ok {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Err(ErrInvalidCertSecret).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrObtainingCertFromSecret)).
			Msgf("Opaque k8s secret %s/%s does not have required field %q", c.namespace, c.secretName, constants.KubernetesOpaqueSecretCAKey)
		return nil, ErrInvalidCertSecret
	}

	cert, err := certificate.NewFromPEM(pemCert, certSecret.Data[constants.KubernetesOpaqueSecretRootPrivateKeyKey])
	if err != nil {
		log.Error().Err(err).Msg("Failed to create new Certificate from PEM")
		return nil, err
	}

	return cert, nil
}
