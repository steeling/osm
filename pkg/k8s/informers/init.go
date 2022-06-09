package informers

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"

	configInformers "github.com/openservicemesh/osm/pkg/gen/client/config/informers/externalversions"
	policyInformers "github.com/openservicemesh/osm/pkg/gen/client/policy/informers/externalversions"

	"github.com/openservicemesh/osm/pkg/constants"
)

// IsMonitoredNamespace returns a boolean indicating if the namespace is among the list of monitored namespaces
func (ic InformerCollection) IsMonitoredNamespace(namespace string) bool {
	_, exists, _ := ic.informers[InformerKeyNamespace].GetStore().GetByKey(namespace)
	return exists
}

// Initializes Namespace monitoring
func (ic *InformerCollection) initNamespaceMonitor() {
	monitorNamespaceLabel := map[string]string{constants.OSMKubeResourceMonitorAnnotation: ic.meshName}

	labelSelector := fields.SelectorFromSet(monitorNamespaceLabel).String()
	option := informers.WithTweakListOptions(func(opt *metav1.ListOptions) {
		opt.LabelSelector = labelSelector
	})

	informerFactory := informers.NewSharedInformerFactoryWithOptions(ic.kubeClient, DefaultKubeEventResyncInterval, option)

	// Add informer
	informer := &informer{
		informer: informerFactory.Core().V1().Namespaces().Informer(),
	}

	customStore := ic.customStores[InformerKeyNamespace]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyNamespace] = informer
}

// Initializes Service monitoring
func (ic *InformerCollection) initServicesMonitor() {
	informerFactory := informers.NewSharedInformerFactory(ic.kubeClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Core().V1().Services().Informer(),
	}

	customStore := ic.customStores[InformerKeyService]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyService] = informer
}

// Initializes Service Account monitoring
func (ic *InformerCollection) initServiceAccountsMonitor() {
	informerFactory := informers.NewSharedInformerFactory(ic.kubeClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Core().V1().ServiceAccounts().Informer(),
	}

	customStore := ic.customStores[InformerKeyServiceAccount]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyServiceAccount] = informer
}

func (ic *InformerCollection) initPodMonitor() {
	informerFactory := informers.NewSharedInformerFactory(ic.kubeClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Core().V1().Pods().Informer(),
	}

	customStore := ic.customStores[InformerKeyPod]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyPod] = informer
}

func (ic *InformerCollection) initEndpointMonitor() {
	informerFactory := informers.NewSharedInformerFactory(ic.kubeClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Core().V1().Endpoints().Informer(),
	}

	customStore := ic.customStores[InformerKeyEndpoints]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyEndpoints] = informer
}

func (ic *InformerCollection) initMeshConfigMonitor() {
	informerFactory := configInformers.NewSharedInformerFactory(ic.configClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Config().V1alpha2().MeshConfigs().Informer(),
	}

	customStore := ic.customStores[InformerKeyMeshConfig]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyMeshConfig] = informer
}

func (ic *InformerCollection) initMeshRootCertificateMonitor() {
	informerFactory := configInformers.NewSharedInformerFactory(ic.configClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Config().V1alpha2().MeshRootCertificates().Informer(),
	}

	customStore := ic.customStores[InformerKeyMeshRootCertificate]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyMeshRootCertificate] = informer
}

func (ic *InformerCollection) initEgressMonitor() {
	informerFactory := policyInformers.NewSharedInformerFactory(ic.policyClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Policy().V1alpha1().Egresses().Informer(),
	}

	customStore := ic.customStores[InformerKeyEgress]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyEgress] = informer
}

func (ic *InformerCollection) initIngressBackendMonitor() {
	informerFactory := policyInformers.NewSharedInformerFactory(ic.policyClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Policy().V1alpha1().IngressBackends().Informer(),
	}

	customStore := ic.customStores[InformerKeyIngressBackend]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyIngressBackend] = informer
}

func (ic *InformerCollection) initUpstreamTrafficSettingMonitor() {
	informerFactory := policyInformers.NewSharedInformerFactory(ic.policyClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Policy().V1alpha1().UpstreamTrafficSettings().Informer(),
	}

	customStore := ic.customStores[InformerKeyUpstreamTrafficSetting]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyUpstreamTrafficSetting] = informer
}

func (ic *InformerCollection) initRetryMonitor() {
	informerFactory := policyInformers.NewSharedInformerFactory(ic.policyClient, DefaultKubeEventResyncInterval)
	informer := &informer{
		informer: informerFactory.Policy().V1alpha1().Retries().Informer(),
	}

	customStore := ic.customStores[InformerKeyRetry]
	if customStore != nil {
		informer.customStore = customStore
	}
	ic.informers[InformerKeyRetry] = informer
}
