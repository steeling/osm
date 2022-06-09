package informers

import (
	"github.com/rs/zerolog/log"
	smiTrafficAccessClient "github.com/servicemeshinterface/smi-sdk-go/pkg/gen/client/access/clientset/versioned"
	smiTrafficSpecClient "github.com/servicemeshinterface/smi-sdk-go/pkg/gen/client/specs/clientset/versioned"
	smiTrafficSplitClient "github.com/servicemeshinterface/smi-sdk-go/pkg/gen/client/split/clientset/versioned"

	smiAccessInformers "github.com/servicemeshinterface/smi-sdk-go/pkg/gen/client/access/informers/externalversions"
	smiTrafficSpecInformers "github.com/servicemeshinterface/smi-sdk-go/pkg/gen/client/specs/informers/externalversions"
	smiTrafficSplitInformers "github.com/servicemeshinterface/smi-sdk-go/pkg/gen/client/split/informers/externalversions"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	configClientset "github.com/openservicemesh/osm/pkg/gen/client/config/clientset/versioned"
	policyClientset "github.com/openservicemesh/osm/pkg/gen/client/policy/clientset/versioned"
	policyInformers "github.com/openservicemesh/osm/pkg/gen/client/policy/informers/externalversions"
)

var (
	k8sInformerKeys = []InformerKey{
		InformerKeyNamespace,
		InformerKeyService,
		InformerKeyServiceAccount,
		InformerKeyPod,
		InformerKeyEndpoints,
	}

	smiInformerKeys = []InformerKey{
		InformerKeyTrafficSplit,
		InformerKeyTrafficTarget,
		InformerKeyHTTPRouteGroup,
		InformerKeyTCPRoute,
	}

	configInformerKeys = []InformerKey{
		InformerKeyMeshConfig,
		InformerKeyMeshRootCertificate,
	}

	policyInformerKeys = []InformerKey{
		InformerKeyEgress,
		InformerKeyIngressBackend,
		InformerKeyUpstreamTrafficSetting,
		InformerKeyRetry,
	}
)

// InformerCollectionOption is a function that modifies an informer collection
type InformerCollectionOption func(*InformerCollection)

// NewInformerCollection creates a new InformerCollection
func NewInformerCollection(meshName string, stop <-chan struct{}, opts ...InformerCollectionOption) (*InformerCollection, error) {
	ic := &InformerCollection{
		meshName:  meshName,
		informers: map[InformerKey]cache.SharedIndexInformer{},
	}

	// Execute all of the given options (e.g. set clients, set custom stores, etc.)
	for _, opt := range opts {
		if opt != nil {
			opt(ic)
		}
	}

	if err := ic.run(stop); err != nil {
		log.Error().Err(err).Msg("Could not start informer collection")
		return nil, err
	}

	return ic, nil
}

// WithKubeClient sets the kubeClient for the InformerCollection
func WithKubeClient(kubeClient kubernetes.Interface) InformerCollectionOption {
	return func(ic *InformerCollection) {
		ic.kubeClient = kubeClient

	}
}

// WithSMIClients sets the SMI clients for the InformerCollection
func WithSMIClients(smiTrafficSplitClient smiTrafficSplitClient.Interface, smiTrafficSpecClient smiTrafficSpecClient.Interface, smiAccessClient smiTrafficAccessClient.Interface) InformerCollectionOption {
	return func(ic *InformerCollection) {
		accessInformerFactory := smiAccessInformers.NewSharedInformerFactory(smiAccessClient, DefaultKubeEventResyncInterval)
		splitInformerFactory := smiTrafficSplitInformers.NewSharedInformerFactory(smiTrafficSplitClient, DefaultKubeEventResyncInterval)
		specInformerFactory := smiTrafficSpecInformers.NewSharedInformerFactory(smiTrafficSpecClient, DefaultKubeEventResyncInterval)

		ic.informers[InformerKeyTCPRoute] = specInformerFactory.Specs().V1alpha4().TCPRoutes().Informer()
		ic.informers[InformerKeyHTTPRouteGroup] = specInformerFactory.Specs().V1alpha4().HTTPRouteGroups().Informer()
		ic.informers[InformerKeyTrafficTarget] = accessInformerFactory.Access().V1alpha3().TrafficTargets().Informer()
		ic.informers[InformerKeyTrafficSplit] = splitInformerFactory.Split().V1alpha2().TrafficSplits().Informer()
	}
}

// WithConfigClient sets the config client for the InformerCollection
func WithConfigClient(configClient configClientset.Interface) InformerCollectionOption {
	return func(ic *InformerCollection) {
		ic.configClient = configClient

		// select the config informers
		for _, key := range configInformerKeys {
			ic.selectedInformers[key] = struct{}{}
		}
	}
}

// WithPolicyClient sets the policy client for the InformerCollection
func WithPolicyClient(policyClient policyClientset.Interface) InformerCollectionOption {
	return func(ic *InformerCollection) {
		ic.policyClient = policyClient

		informerFactory := policyInformers.NewSharedInformerFactory(policyClient, DefaultKubeEventResyncInterval)
		ic.informers[InformerKeyUpstreamTrafficSetting] = informerFactory.Policy().V1alpha1().UpstreamTrafficSettings().Informer()

		// select the policy informers
		for _, key := range policyInformerKeys {
			ic.selectedInformers[key] = struct{}{}
		}
	}
}

func (ic *InformerCollection) run(stop <-chan struct{}) error {
	log.Info().Msg("InformerCollection started")
	var hasSynced []cache.InformerSynced
	var names []string

	if ic.informers == nil {
		return errInitInformers
	}

	for name, informer := range ic.informers {
		if informer == nil {
			continue
		}

		go informer.Run(stop)
		names = append(names, string(name))
		log.Info().Msgf("Waiting for %s informer cache sync...", name)
		hasSynced = append(hasSynced, informer.HasSynced)
	}

	if !cache.WaitForCacheSync(stop, hasSynced...) {
		return errSyncingCaches
	}

	log.Info().Msgf("Caches for %v synced successfully", names)

	return nil
}

// AddEventHandler adds an handler to the informer indexed by the given InformerKey
func (ic *InformerCollection) AddEventHandler(informerKey InformerKey, handler cache.ResourceEventHandler) {
	i, ok := ic.informers[informerKey]
	if !ok {
		log.Info().Msgf("attempted to add event handler for nil informer %s", informerKey)
		return
	}

	i.informer.AddEventHandler(handler)
}

// GetByKey retrieves an item (based on the given index) from the store of the informer indexed by the given InformerKey
func (ic *InformerCollection) GetByKey(informerKey InformerKey, objectKey string) (interface{}, bool, error) {
	informer, ok := ic.informers[informerKey]
	if !ok {
		// keithmattix: This is the silent failure option, but perhaps we want to return an error?
		return nil, false, nil
	}

	return informer.GetStore().GetByKey(objectKey)
}

// List returns the contents of the store of the informer indexed by the given InformerKey
func (ic *InformerCollection) List(informerKey InformerKey) []interface{} {
	informer, ok := ic.informers[informerKey]
	if !ok {
		// keithmattix: This is the silent failure option, but perhaps we want to return an error?
		return nil
	}

	return informer.GetStore().List()
}
