package kubernetes

import (
	"fmt"
	"strings"

	goversion "github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openservicemesh/osm/pkg/constants"
)

// GetHostnamesForService returns a list of hostnames over which the service can be accessed within the local cluster.
// If 'sameNamespace' is set to true, then the shorthand hostnames service and service:port are also returned.
func GetHostnamesForService(service *corev1.Service, sameNamespace bool, clusterDomains ...string) []string {
	// TODO(steeling) the gateway should not accept cluster.local domain.
	// The gateway should accept the cluster ID for this cluster.
	// The gateway should accept .cluster.global

	// Sidecars outbound policies will need to use this config as is.
	// Siecars inbound policies will need to add the cluster ID and cluster.global

	var domains []string
	if service == nil {
		return domains
	}

	serviceName := service.Name
	namespace := service.Namespace

	if sameNamespace {
		// Within the same namespace, service name is resolvable to its address
		domains = append(domains, serviceName) // service
	}

	domains = append(domains, fmt.Sprintf("%s.%s", serviceName, namespace))             // service.namespace
	domains = append(domains, fmt.Sprintf("%s.%s.svc", serviceName, namespace))         // service.namespace.svc
	domains = append(domains, fmt.Sprintf("%s.%s.svc.cluster", serviceName, namespace)) // service.namespace.svc.cluster
	for _, domain := range clusterDomains {
		domains = append(domains, fmt.Sprintf("%s.%s.svc.%s", serviceName, namespace, domain)) // service.namespace.svc.$domain
	}
	for _, portSpec := range service.Spec.Ports {
		port := portSpec.Port

		if sameNamespace {
			// Within the same namespace, service name is resolvable to its address
			domains = append(domains, fmt.Sprintf("%s:%d", serviceName, port)) // service:port
		}

		domains = append(domains, fmt.Sprintf("%s.%s:%d", serviceName, namespace, port))             // service.namespace:port
		domains = append(domains, fmt.Sprintf("%s.%s.svc:%d", serviceName, namespace, port))         // service.namespace.svc:port
		domains = append(domains, fmt.Sprintf("%s.%s.svc.cluster:%d", serviceName, namespace, port)) // service.namespace.svc.cluster:port
		for _, domain := range clusterDomains {
			domains = append(domains, fmt.Sprintf("%s.%s.svc.%s:%d", serviceName, namespace, domain, port)) // service.namespace.svc.$domain:port
		}
	}
	return domains
}

// GetServiceFromHostname returns the service name from its hostname
func GetServiceFromHostname(host string) string {
	// The service name is the first string in the host name for a service.
	// Ex. service.namespace, service.namespace.cluster.local
	service := strings.Split(host, ".")[0]

	// For services that are not namespaced the service name contains the port as well
	// Ex. service:port
	return strings.Split(service, ":")[0]
}

// GetAppProtocolFromPortName returns the port's application protocol from its name, defaults to 'http' if not specified.
func GetAppProtocolFromPortName(portName string) string {
	portName = strings.ToLower(portName)

	switch {
	case strings.HasPrefix(portName, "http-"):
		return "http"

	case strings.HasPrefix(portName, "tcp-"):
		return "tcp"

	case strings.HasPrefix(portName, "grpc-"):
		return "grpc"

	default:
		return constants.ProtocolHTTP
	}
}

// GetKubernetesServerVersionNumber returns the Kubernetes server version number in chunks, ex. v1.19.3 => [1, 19, 3]
func GetKubernetesServerVersionNumber(kubeClient kubernetes.Interface) ([]int, error) {
	if kubeClient == nil {
		return nil, errors.Errorf("Kubernetes client is not initialized")
	}

	version, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return nil, errors.Errorf("Error getting K8s server version: %s", err)
	}

	ver, err := goversion.NewVersion(version.String())
	if err != nil {
		return nil, errors.Errorf("Error parsing k8s server version %s: %s", version, err)
	}

	return ver.Segments(), nil
}
