package registry

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/k8s"
	"github.com/openservicemesh/osm/pkg/service"
)

// ProxyServiceMapper knows how to map Envoy instances to services.
type ProxyServiceMapper interface {
	ListProxyServices(*envoy.Proxy) ([]service.MeshService, error)
}

// ExplicitProxyServiceMapper is a custom ProxyServiceMapper implementation.
type ExplicitProxyServiceMapper func(*envoy.Proxy) ([]service.MeshService, error)

// ListProxyServices executes the given mapping.
func (e ExplicitProxyServiceMapper) ListProxyServices(p *envoy.Proxy) ([]service.MeshService, error) {
	return e(p)
}

// KubeProxyServiceMapper maps an Envoy instance to services in a Kubernetes cluster.
type KubeProxyServiceMapper struct {
	KubeController k8s.Controller
}

// ListProxyServices maps an Envoy instance to a number of Kubernetes services.
func (k *KubeProxyServiceMapper) ListProxyServices(p *envoy.Proxy) ([]service.MeshService, error) {
	pod, err := k.KubeController.GetPodForProxy(p)
	if err != nil {
		return nil, err
	}

	meshServices := listServicesForPod(pod, k.KubeController)

	servicesForPod := strings.Join(listServiceNames(meshServices), ",")
	log.Trace().Msgf("Services associated with Pod with UID=%s Name=%s/%s: %+v",
		pod.ObjectMeta.UID, pod.Namespace, pod.Name, servicesForPod)

	return meshServices, nil
}

func kubernetesServicesToMeshServices(kubeController k8s.Controller, kubernetesServices []v1.Service, subdomainFilter string) (meshServices []service.MeshService) {
	for _, svc := range kubernetesServices {
		for _, meshSvc := range k8s.ServiceToMeshServices(kubeController, svc) {
			if meshSvc.Subdomain() == subdomainFilter || meshSvc.Subdomain() == "" {
				meshServices = append(meshServices, meshSvc)
			}
		}
	}
	return meshServices
}

func listServiceNames(meshServices []service.MeshService) (serviceNames []string) {
	for _, meshService := range meshServices {
		serviceNames = append(serviceNames, fmt.Sprintf("%s/%s", meshService.Namespace, meshService.Name))
	}
	return serviceNames
}

// listServicesForPod lists Kubernetes services whose selectors match pod labels
func listServicesForPod(pod *v1.Pod, kubeController k8s.Controller) []service.MeshService {
	var serviceList []v1.Service
	svcList := kubeController.ListServices()

	for _, svc := range svcList {
		if svc.Namespace != pod.Namespace {
			continue
		}
		svcRawSelector := svc.Spec.Selector
		// service has no selectors, we do not need to match against the pod label
		if len(svcRawSelector) == 0 {
			continue
		}
		selector := labels.Set(svcRawSelector).AsSelector()
		if selector.Matches(labels.Set(pod.Labels)) {
			serviceList = append(serviceList, *svc)
		}
	}

	if len(serviceList) == 0 {
		return nil
	}

	meshServices := kubernetesServicesToMeshServices(kubeController, serviceList, pod.GetName())

	return meshServices
}

func getCertCommonNameForPod(pod v1.Pod) (certificate.CommonName, error) {
	proxyUIDStr, exists := pod.Labels[constants.EnvoyUniqueIDLabelName]
	if !exists {
		return "", errors.Errorf("no %s label", constants.EnvoyUniqueIDLabelName)
	}
	proxyUID, err := uuid.Parse(proxyUIDStr)
	if err != nil {
		return "", errors.Wrapf(err, "invalid UID value for %s label", constants.EnvoyUniqueIDLabelName)
	}
	return certificate.CommonName(fmt.Sprintf("%s.%s.%s.%s.cluster.local", proxyUID, envoy.KindSidecar, pod.Spec.ServiceAccountName, pod.Namespace)), nil
}
