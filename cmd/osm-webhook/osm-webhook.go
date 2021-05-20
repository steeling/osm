// Command osm-webhook starts up a Kubernetes Validating Webhook on the
// specified port, listening for requests over HTTPS.
package main

import (
	"crypto/tls"
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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// validatingWebhookServiceName is the name of the OSM Validating Webhook service
	validatingWebhookServiceName = "osm-webhook"
	WebhookCertificateSecretName = "validating-webhook-cert-secret"
)

var (
	verbosity          string
	meshName           string
	kubeConfigFile     string
	osmNamespace       string
	osmMeshConfigName  string
	certProviderKind   string
	caBundleSecretName string

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
	flags.StringVar(&osmNamespace, "osm-namespace", "", "Namespace to which OSM belongs to.")
	flags.StringVar(&osmMeshConfigName, "osm-config-name", "osm-mesh-config", "Name of the OSM MeshConfig")
	flags.StringVar(&meshName, "mesh-name", "", "OSM mesh name")
	flags.StringVar(&certProviderKind, "certificate-manager", providers.TresorKind.String(), fmt.Sprintf("Certificate manager, one of [%v]", providers.ValidCertificateProviders))
	flags.StringVar(&caBundleSecretName, "ca-bundle-secret-name", "", "Name of the Kubernetes Secret for the OSM CA bundle")
}

func parseFlags() error {
	if err := flags.Parse(os.Args); err != nil {
		return err
	}
	_ = flag.CommandLine.Parse([]string{})
	return nil
}

func main() {
	log.Info().Msgf("Starting osm-webhook %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)

	if err := logger.SetLogLevel(verbosity); err != nil {
		log.Fatal().Err(err).Msg("Error setting log level")
		return
	}

	stop := signals.RegisterExitHandlers()

	serveMux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprint(":", *port),
		Handler: serveMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{},
		},
	}

	serveMux.Handle("/version", version.GetVersionHandler())
	serveMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, "hello world")
	}))
	serveMux.Handle("/health/ready", health.ReadinessHandler(nil, nil))
	serveMux.Handle("/health/alive", health.LivenessHandler(nil, nil))

	// TODO: Do we need to add metrics stuff?

	cert := getCertificate(stop)

	// #nosec G402
	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Error().Err(err).Msgf("Failed to start OSM metrics/probes HTTP server")
	}

	<-stop
	log.Info().Msgf("Stopping osm-webhook %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
}

func getCertificate(stop <-chan struct{}) tls.Certificate {
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

	webhookHandlerCert, err = providers.GetCertificateFromSecret(osmNamespace, WebhookCertificateSecretName, webhookHandlerCert, kubeClient)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching webhook certificate from k8s secret: %s", err)
	}

	// Generate a key pair from your pem-encoded cert and key ([]byte).
	cert, err := tls.X509KeyPair(webhookHandlerCert.GetCertificateChain(), webhookHandlerCert.GetPrivateKey())
	if err != nil {
		log.Error().Err(err).Msg("Error parsing webhook certificate")
	}

	return cert
}
