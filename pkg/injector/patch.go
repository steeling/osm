package injector

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/metricsstore"
)

// Note that this will mutate the pod object.
func (wh *mutatingWebhook) createPatch(pod *corev1.Pod, req *admissionv1.AdmissionRequest, proxyUUID uuid.UUID) ([]byte, error) {
	namespace := req.Namespace

	// Issue a certificate for the proxy sidecar - used for Envoy to connect to XDS (not Envoy-to-Envoy connections)
	cn := envoy.NewXDSCertCommonName(proxyUUID, envoy.KindSidecar, pod.Spec.ServiceAccountName, namespace)
	log.Debug().Msgf("Patching POD spec: service-account=%s, namespace=%s with certificate CN=%s", pod.Spec.ServiceAccountName, namespace, cn)
	startTime := time.Now()
	bootstrapCertificate, err := wh.certManager.IssueCertificate(cn, constants.XDSCertificateValidityPeriod)
	if err != nil {
		log.Error().Err(err).Msgf("Error issuing bootstrap certificate for Envoy with CN=%s", cn)
		return nil, err
	}
	elapsed := time.Since(startTime)

	metricsstore.DefaultMetricsStore.CertIssuedCount.Inc()
	metricsstore.DefaultMetricsStore.CertIssuedTime.
		WithLabelValues().Observe(elapsed.Seconds())
	originalHealthProbes := rewriteHealthProbes(pod)

	// Create the bootstrap configuration for the Envoy proxy for the given pod
	envoyBootstrapConfigName := fmt.Sprintf("envoy-bootstrap-config-%s", proxyUUID)

	// The webhook has a side effect (making out-of-band changes) of creating k8s secret
	// corresponding to the Envoy bootstrap config. Such a side effect needs to be skipped
	// when the request is a DryRun.
	// Ref: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#side-effects
	if req.DryRun != nil && *req.DryRun {
		log.Debug().Msgf("Skipping envoy bootstrap config creation for dry-run request: service-account=%s, namespace=%s", pod.Spec.ServiceAccountName, namespace)
	} else if _, err = wh.createEnvoyBootstrapConfig(envoyBootstrapConfigName, namespace, wh.osmNamespace, bootstrapCertificate, originalHealthProbes); err != nil {
		log.Error().Err(err).Msgf("Failed to create Envoy bootstrap config for pod: service-account=%s, namespace=%s, certificate CN=%s", pod.Spec.ServiceAccountName, namespace, cn)
		return nil, err
	}

	// Create volume for envoy TLS secret
	pod.Spec.Volumes = append(pod.Spec.Volumes, getVolumeSpec(envoyBootstrapConfigName)...)
	// On Windows we cannot use init containers to program HNS because it requires elevated privileges
	// As a result we assume that the HNS redirection policies are already programmed via a CNI plugin.
	// Skip adding the init container and only patch the pod spec with sidecar container.
	podOS := pod.Spec.NodeSelector["kubernetes.io/os"]
	if err := wh.verifyPrerequisites(podOS); err != nil {
		return nil, err
	}

	err = wh.configurePodInit(podOS, pod, namespace)
	if err != nil {
		return nil, err
	}

	if (originalHealthProbes.liveness != nil && originalHealthProbes.liveness.isTCPSocket) ||
		(originalHealthProbes.readiness != nil && originalHealthProbes.readiness.isTCPSocket) ||
		(originalHealthProbes.startup != nil && originalHealthProbes.startup.isTCPSocket) {
		healthcheckContainer := corev1.Container{
			Name:            "osm-healthcheck",
			Image:           os.Getenv("OSM_DEFAULT_HEALTHCHECK_CONTAINER_IMAGE"),
			ImagePullPolicy: wh.osmContainerPullPolicy,
			Args: []string{
				"--verbosity", log.GetLevel().String(),
			},
			Command: []string{
				"/osm-healthcheck",
			},
			Ports: []corev1.ContainerPort{
				{
					ContainerPort: healthcheckPort,
				},
			},
		}
		pod.Spec.Containers = append(pod.Spec.Containers, healthcheckContainer)
	}

	// Add the Envoy sidecar
	sidecar := getEnvoySidecarContainerSpec(pod, wh.configurator, originalHealthProbes, podOS)
	pod.Spec.Containers = append(pod.Spec.Containers, sidecar)

	enableMetrics, err := wh.isMetricsEnabled(namespace)
	if err != nil {
		log.Error().Err(err).Msgf("Error checking if namespace %s is enabled for metrics", namespace)
		return nil, err
	}
	if enableMetrics {
		if pod.Annotations == nil {
			pod.Annotations = make(map[string]string)
		}
		pod.Annotations[constants.PrometheusScrapeAnnotation] = strconv.FormatBool(true)
		pod.Annotations[constants.PrometheusPortAnnotation] = strconv.Itoa(constants.EnvoyPrometheusInboundListenerPort)
		pod.Annotations[constants.PrometheusPathAnnotation] = constants.PrometheusScrapePath
	}

	// This will append a label to the pod, which points to the unique Envoy ID used in the
	// xDS certificate for that Envoy. This label will help xDS match the actual pod to the Envoy that
	// connects to xDS (with the certificate's CN matching this label).
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels[constants.EnvoyUniqueIDLabelName] = proxyUUID.String()

	return json.Marshal(makePatches(req, pod))
}

// verifyPrerequisites verifies if the prerequisites to patch the request are met by returning an error if unmet
func (wh *mutatingWebhook) verifyPrerequisites(podOS string) error {
	isWindows := strings.EqualFold(podOS, constants.OSWindows)

	// Verify that the required images are configured
	if image := wh.configurator.GetEnvoyImage(); !isWindows && image == "" {
		// Linux pods require Envoy Linux image
		return errors.New("MeshConfig sidecar.envoyImage not set")
	}
	if image := wh.configurator.GetEnvoyWindowsImage(); isWindows && image == "" {
		// Windows pods require Envoy Windows image
		return errors.New("MeshConfig sidecar.envoyWindowsImage not set")
	}
	if image := wh.configurator.GetInitContainerImage(); !isWindows && image == "" {
		// Linux pods require init container image
		return errors.New("MeshConfig sidecar.initContainerImage not set")
	}

	return nil
}

func (wh *mutatingWebhook) configurePodInit(podOS string, pod *corev1.Pod, namespace string) error {
	if strings.EqualFold(podOS, constants.OSWindows) {
		// No init container for Windows
		return nil
	}

	// Build outbound port exclusion list
	podOutboundPortExclusionList, err := getPortExclusionListForPod(pod, namespace, outboundPortExclusionListAnnotation)
	if err != nil {
		return err
	}
	globalOutboundPortExclusionList := wh.configurator.GetMeshConfig().Spec.Traffic.OutboundPortExclusionList
	outboundPortExclusionList := mergePortExclusionLists(podOutboundPortExclusionList, globalOutboundPortExclusionList)

	// Build inbound port exclusion list
	podInboundPortExclusionList, err := getPortExclusionListForPod(pod, namespace, inboundPortExclusionListAnnotation)
	if err != nil {
		return err
	}
	globalInboundPortExclusionList := wh.configurator.GetMeshConfig().Spec.Traffic.InboundPortExclusionList
	inboundPortExclusionList := mergePortExclusionLists(podInboundPortExclusionList, globalInboundPortExclusionList)

	// Build the outbound IP range exclusion list
	podOutboundIPRangeExclusionList, err := getOutboundIPRangeListForPod(pod, namespace, outboundIPRangeExclusionListAnnotation)
	if err != nil {
		return err
	}
	globalOutboundIPRangeExclusionList := wh.configurator.GetMeshConfig().Spec.Traffic.OutboundIPRangeExclusionList
	outboundIPRangeExclusionList := mergeIPRangeLists(podOutboundIPRangeExclusionList, globalOutboundIPRangeExclusionList)

	// Build the outbound IP range inclusion list
	podOutboundIPRangeInclusionList, err := getOutboundIPRangeListForPod(pod, namespace, outboundIPRangeInclusionListAnnotation)
	if err != nil {
		return err
	}
	globalOutboundIPRangeInclusionList := wh.configurator.GetMeshConfig().Spec.Traffic.OutboundIPRangeInclusionList
	outboundIPRangeInclusionList := mergeIPRangeLists(podOutboundIPRangeInclusionList, globalOutboundIPRangeInclusionList)

	// Add the init container to the pod spec
	initContainer := getInitContainerSpec(constants.InitContainerName, wh.configurator, outboundIPRangeExclusionList, outboundIPRangeInclusionList, outboundPortExclusionList, inboundPortExclusionList, wh.configurator.IsPrivilegedInitContainer(), wh.osmContainerPullPolicy)
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, initContainer)

	return nil
}

func makePatches(req *admissionv1.AdmissionRequest, pod *corev1.Pod) []jsonpatch.JsonPatchOperation {
	original := req.Object.Raw
	current, err := json.Marshal(pod)
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingKubernetesResource)).
			Msgf("Error marshaling Pod with UID=%s", pod.ObjectMeta.UID)
	}
	admissionResponse := admission.PatchResponseFromRaw(original, current)
	return admissionResponse.Patches
}

func alreadyInjected(pod *corev1.Pod) bool {
	return pod.Labels != nil && pod.Labels[constants.EnvoyUniqueIDLabelName] != ""
}

func (wh *mutatingWebhook) maybeStripOSMConfiguration(pod *corev1.Pod, namespace string) error {
	fmt.Println("already injected? ", alreadyInjected(pod))
	if !alreadyInjected(pod) {
		return nil
	}
	fmt.Println("here!!!!")
	// Strip out the OSM configuration from the pod

	// 1. The init container
	for i, c := range pod.Spec.InitContainers {
		if c.Name == constants.InitContainerName {
			fmt.Println("FOUND AN INIT CONTAINER!!!!")
			pod.Spec.InitContainers = append(pod.Spec.InitContainers[:i], pod.Spec.InitContainers[i+1:]...)
		}
	}
	fmt.Println("but did i remove it???", pod.Spec.InitContainers)

	// 2. The prior annotations
	metricsEnabled, err := wh.isMetricsEnabled(namespace)
	if err != nil {
		return err
	}

	delete(pod.Labels, constants.EnvoyUniqueIDLabelName)
	if metricsEnabled {
		delete(pod.Annotations, constants.PrometheusScrapeAnnotation)
		delete(pod.Annotations, constants.PrometheusPortAnnotation)
		delete(pod.Annotations, constants.PrometheusPathAnnotation)
	}

	// 3. The envoy sidecar, should be the last, but we double check.
	for i, c := range pod.Spec.Containers {
		if c.Name == constants.EnvoyContainerName {
			pod.Spec.Containers = append(pod.Spec.Containers[:i], pod.Spec.Containers[i+1:]...)
		}
	}

	// 4. Bootstrap volume, should be the last volume, but we double check.
	for i, v := range pod.Spec.Volumes {
		if v.Name == envoyBootstrapConfigVolume {
			pod.Spec.Volumes = append(pod.Spec.Volumes[:i], pod.Spec.Volumes[i+1:]...)
		}
	}
	fmt.Println("volume is now", pod.Spec.Volumes)

	// Undo health probes.
	// func rewriteHealthProbes(pod *corev1.Pod) healthProbes {
	//
	// undo healthcheck container if it exists...
	return nil
}
