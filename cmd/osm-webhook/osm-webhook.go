// Command osm-webhook starts up a Kubernetes Validating Webhook on the
// specified port, listening for requests over HTTPS.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/certificate/providers"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/constants"
	configClientset "github.com/openservicemesh/osm/pkg/gen/client/config/clientset/versioned"
	"github.com/openservicemesh/osm/pkg/health"
	"github.com/openservicemesh/osm/pkg/kubernetes/events"
	"github.com/openservicemesh/osm/pkg/logger"
	"github.com/openservicemesh/osm/pkg/signals"
	"github.com/openservicemesh/osm/pkg/version"
	"github.com/spf13/pflag"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// validatingWebhookServiceName is the name of the OSM Validating Webhook service
	validatingWebhookServiceName = "osm-webhook"
	WebhookCertificateSecretName = "validating-webhook-cert-secret"
	ValidatingWebhookName        = "osm-validate-webhook.k8s.io"
)

var (
	verbosity          string
	kubeConfigFile     string
	osmNamespace       string
	osmMeshConfigName  string
	certProviderKind   string
	caBundleSecretName string
	webhookConfigName  string

	tresorOptions      providers.TresorOptions
	vaultOptions       providers.VaultOptions
	certManagerOptions providers.CertManagerOptions
)

var (
	flags = pflag.NewFlagSet(`osm-webhook`, pflag.ExitOnError)
	port  = flags.Int("port", constants.OSMWebhookPort, "osm webhook port")
	log   = logger.New("osm-webhook/main")
)

func init() {
	flags.StringVarP(&verbosity, "verbosity", "v", "info", "Set log verbosity level")
	flags.StringVar(&kubeConfigFile, "kubeconfig", "", "Path to Kubernetes config file.")
	flags.StringVar(&osmNamespace, "osm-namespace", "osm-system", "Namespace to which OSM belongs to.")
	flags.StringVar(&osmMeshConfigName, "osm-config-name", "osm-mesh-config", "Name of the OSM MeshConfig")
	flags.StringVar(&webhookConfigName, "webhook-config-name", "osm-webhook-osm", "Name of the ValidatingWebhookConfiguration to be configured by osm-injector")
	// Generic certificate manager/provider options
	flags.StringVar(&certProviderKind, "certificate-manager", providers.TresorKind.String(), fmt.Sprintf("Certificate manager, one of [%v]", providers.ValidCertificateProviders))
	flags.StringVar(&caBundleSecretName, "ca-bundle-secret-name", "osm-ca-bundle", "Name of the Kubernetes Secret for the OSM CA bundle")

	// Vault certificate manager/provider options
	flags.StringVar(&vaultOptions.VaultProtocol, "vault-protocol", "http", "Host name of the Hashi Vault")
	flags.StringVar(&vaultOptions.VaultHost, "vault-host", "vault.default.svc.cluster.local", "Host name of the Hashi Vault")
	flags.StringVar(&vaultOptions.VaultToken, "vault-token", "", "Secret token for the the Hashi Vault")
	flags.StringVar(&vaultOptions.VaultRole, "vault-role", "openservicemesh", "Name of the Vault role dedicated to Open Service Mesh")
	flags.IntVar(&vaultOptions.VaultPort, "vault-port", 8200, "Port of the Hashi Vault")

	// Cert-manager certificate manager/provider options
	flags.StringVar(&certManagerOptions.IssuerName, "cert-manager-issuer-name", "osm-ca", "cert-manager issuer name")
	flags.StringVar(&certManagerOptions.IssuerKind, "cert-manager-issuer-kind", "Issuer", "cert-manager issuer kind")
	flags.StringVar(&certManagerOptions.IssuerGroup, "cert-manager-issuer-group", "cert-manager.io", "cert-manager issuer group")
}

func parseFlags() error {
	if err := flags.Parse(os.Args); err != nil {
		return err
	}
	_ = flag.CommandLine.Parse([]string{})
	return nil
}

func main() {
	ctx := context.Background()
	log.Info().Msgf("Starting osm-webhook %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)

	if err := parseFlags(); err != nil {
		log.Fatal().Err(err).Msg("Error parsing cmd line arguments")
	}

	if err := logger.SetLogLevel(verbosity); err != nil {
		log.Fatal().Err(err).Msg("Error setting log level")
		return
	}

	// Initialize kube config and client
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error creating kube config (kubeconfig=%s)", kubeConfigFile)
	}
	kubeClient := kubernetes.NewForConfigOrDie(kubeConfig)

	// Initialize the generic Kubernetes event recorder and associate it with the osm-webhook pod resource
	webhookPod, err := getWebhookPod(ctx, kubeClient)
	if err != nil {
		log.Fatal().Msg("Error fetching osm-webhook pod")
	}

	if err := events.GenericEventRecorder().Initialize(webhookPod, kubeClient, osmNamespace); err != nil {
		log.Fatal().Msg("Error initializing generic event recorder")
	}

	stop := signals.RegisterExitHandlers()

	serveMux := http.NewServeMux()

	serveMux.Handle("/version", version.GetVersionHandler())
	serveMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "hello world")
	}))
	serveMux.Handle("/health/ready", health.ReadinessHandler(nil, nil))
	serveMux.Handle("/health/alive", health.LivenessHandler(nil, nil))

	// TODO: Do we need to add metrics stuff?

	certificater := getCertificate(stop)

	// Generate a key pair from your pem-encoded cert and key ([]byte).
	cert, err := tls.X509KeyPair(certificater.GetCertificateChain(), certificater.GetPrivateKey())
	if err != nil {
		log.Error().Err(err).Msg("Error parsing webhook certificate")
	}

	server := &http.Server{
		Addr:    fmt.Sprint(":", *port),
		Handler: serveMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	updateValidatingWebhookCABundle(ctx, certificater, webhookConfigName, kubeClient)
	go func() {
		<-stop
		log.Info().Msgf("Stopping osm-webhook %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
		if err := server.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msgf("Error shutting down server: %s", err)
		}
	}()
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Error().Err(err).Msgf("Exiting HTTP server with %s", err)
	}

}

// getWebhookPod returns the osm-webhook pod spec.
// The pod name is inferred from the 'WEBHOOK_POD_NAME' env variable which is set during deployment.
func getWebhookPod(ctx context.Context, kubeClient kubernetes.Interface) (*corev1.Pod, error) {
	podName := os.Getenv("WEBHOOK_POD_NAME")
	if podName == "" {
		return nil, errors.New("WEBHOOK_POD_NAME env variable cannot be empty")
	}

	pod, err := kubeClient.CoreV1().Pods(osmNamespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		log.Error().Err(err).Msgf("Error retrieving osm-webhook pod %s", podName)
		return nil, err
	}

	return pod, nil
}

func getCertificate(stop <-chan struct{}) certificate.Certificater {
	// Initialize kube config and client
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error creating kube config (kubeconfig=%s)", kubeConfigFile)
	}
	kubeClient := kubernetes.NewForConfigOrDie(kubeConfig)

	// Initialize Configurator to retrieve mesh specific config
	cfg := configurator.NewConfigurator(configClientset.NewForConfigOrDie(kubeConfig), stop, osmNamespace, osmMeshConfigName)
	meshConfig, err := cfg.GetMeshConfigJSON()
	if err != nil {
		log.Error().Err(err).Msgf("Error parsing MeshConfig %s", osmMeshConfigName)
	}
	log.Info().Msgf("Initial MeshConfig %s: %v", osmMeshConfigName, meshConfig)

	// Intitialize certificate manager/provider
	certProviderConfig := providers.NewCertificateProviderConfig(kubeClient, kubeConfig, cfg, providers.Kind(certProviderKind), osmNamespace,
		caBundleSecretName, tresorOptions, vaultOptions, certManagerOptions)

	certManager, _, err := certProviderConfig.GetCertificateManager()
	if err != nil {
		events.GenericEventRecorder().FatalEvent(err, events.InvalidCertificateManager,
			"Error initializing certificate manager of kind %s", certProviderKind)
	}

	webhookHandlerCert, err := certManager.IssueCertificate(
		certificate.CommonName(fmt.Sprintf("%s.%s.svc", validatingWebhookServiceName, osmNamespace)),
		constants.XDSCertificateValidityPeriod)

	if err != nil {
		log.Error().Err(err).Msgf("Error issuing certificate for the validating webhook: %+v", err)
	}

	webhookHandlerCert, err = providers.GetCertificateFromSecret(osmNamespace, "validating-webhook-cert-secret", webhookHandlerCert, kubeClient)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching webhook certificate from k8s secret: %s", err)
	}

	return webhookHandlerCert
}

// updateMutatingWebhookCABundle updates the existing MutatingWebhookConfiguration with the CA this OSM instance runs with.
// It is necessary to perform this patch because the original MutatingWebhookConfig YAML does not contain the root certificate.
func updateValidatingWebhookCABundle(ctx context.Context, cert certificate.Certificater, name string, clientSet kubernetes.Interface) error {
	log.Info().Msgf("going to updating CA Bundle for MutatingWebhookConfiguration %s", name)
	vwc := clientSet.AdmissionregistrationV1().ValidatingWebhookConfigurations()

	patchJSON, err := json.Marshal(getPartialValidatingWebhookConfiguration(cert, name))
	if err != nil {
		return err
	}

	if _, err = vwc.Patch(ctx, name, types.StrategicMergePatchType, patchJSON, metav1.PatchOptions{}); err != nil {
		log.Error().Err(err).Msgf("Error updating CA Bundle for ValidatingWebhookConfiguration %s", name)
		return err
	}

	log.Info().Msgf("Finished updating CA Bundle for MutatingWebhookConfiguration %s", name)
	return nil
}

// getPartialValidatingWebhookConfiguration returns only the portion of the MutatingWebhookConfiguration that needs to be updated.
func getPartialValidatingWebhookConfiguration(cert certificate.Certificater, name string) admissionregv1.ValidatingWebhookConfiguration {
	return admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Webhooks: []admissionregv1.ValidatingWebhook{
			{
				Name: ValidatingWebhookName,
				ClientConfig: admissionregv1.WebhookClientConfig{
					CABundle: cert.GetCertificateChain(),
				},
				SideEffects: func() *admissionregv1.SideEffectClass {
					sideEffect := admissionregv1.SideEffectClassNoneOnDryRun
					return &sideEffect
				}(),
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}
}
