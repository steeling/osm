package generator

import (
	"context"
	"fmt"
	"testing"
	"time"

	xds_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	xds_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	xds_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	xds_auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	access "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/access/v1alpha3"
	specs "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/specs/v1alpha4"
	split "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/split/v1alpha2"
	tassert "github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
	testclient "k8s.io/client-go/kubernetes/fake"

	"github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	configv1alpha2 "github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	"github.com/openservicemesh/osm/pkg/catalog"
	tresorFake "github.com/openservicemesh/osm/pkg/certificate/providers/tresor/fake"
	"github.com/openservicemesh/osm/pkg/compute"
	"github.com/openservicemesh/osm/pkg/endpoint"
	"github.com/openservicemesh/osm/pkg/envoy/generator/lds"
	"github.com/openservicemesh/osm/pkg/envoy/secrets"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/service"
	"github.com/openservicemesh/osm/pkg/smi"

	catalogFake "github.com/openservicemesh/osm/pkg/catalog/fake"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/tests"
)

func getProxy(kubeClient kubernetes.Interface) (*envoy.Proxy, error) {
	podLabels := map[string]string{
		constants.AppLabel:               tests.BookbuyerService.Name,
		constants.EnvoyUniqueIDLabelName: tests.ProxyUUID,
	}
	if _, err := tests.MakePod(kubeClient, tests.Namespace, tests.BookbuyerServiceName, tests.BookbuyerServiceAccountName, podLabels); err != nil {
		return nil, err
	}

	selectors := map[string]string{
		constants.AppLabel: tests.BookbuyerServiceName,
	}
	if _, err := tests.MakeService(kubeClient, tests.BookbuyerServiceName, selectors); err != nil {
		return nil, err
	}

	for _, svcName := range []string{tests.BookstoreApexServiceName, tests.BookstoreV1ServiceName, tests.BookstoreV2ServiceName} {
		selectors := map[string]string{
			constants.AppLabel: "bookstore",
		}
		if _, err := tests.MakeService(kubeClient, svcName, selectors); err != nil {
			return nil, err
		}
	}

	return envoy.NewProxy(envoy.KindSidecar, uuid.MustParse(tests.ProxyUUID), tests.BookbuyerServiceIdentity, nil, 1), nil
}

func TestEndpointConfiguration(t *testing.T) {
	assert := tassert.New(t)
	kubeClient := testclient.NewSimpleClientset()

	mockCtrl := gomock.NewController(t)
	provider := compute.NewMockInterface(mockCtrl)
	provider.EXPECT().ListEndpointsForService(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().ListEgressPoliciesForServiceAccount(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().GetIngressBackendPolicyForService(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().GetUpstreamTrafficSettingByService(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().GetUpstreamTrafficSettingByNamespace(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().ListServices().Return([]service.MeshService{tests.BookstoreV1Service}).AnyTimes()
	provider.EXPECT().GetMeshConfig().Return(v1alpha2.MeshConfig{Spec: v1alpha2.MeshConfigSpec{
		Traffic: v1alpha2.TrafficSpec{
			EnablePermissiveTrafficPolicyMode: true,
		},
	}}).AnyTimes()

	meshCatalog := catalogFake.NewFakeMeshCatalog(provider)

	proxy, err := getProxy(kubeClient)
	assert.Empty(err)
	assert.NotNil(meshCatalog)
	assert.NotNil(proxy)

	proxy = envoy.NewProxy(envoy.KindSidecar, uuid.MustParse(tests.ProxyUUID), tests.BookbuyerServiceIdentity, nil, 1)
	g := NewEnvoyConfigGenerator(meshCatalog, nil, nil)
	resources, err := g.generateEDS(context.Background(), proxy)
	assert.Nil(err)
	assert.NotNil(resources)

	// There are 3 endpoints configured based on the configuration:
	// 1. Bookstore
	// 2. Bookstore-v1
	// 3. Bookstore-v2
	assert.Len(resources, 1)

	loadAssignment, ok := resources[0].(*xds_endpoint.ClusterLoadAssignment)

	// validating an endpoint
	assert.True(ok)
	assert.Len(loadAssignment.Endpoints, 1)
}

// TestNewResponse sets up a fake kube client, then a pod and makes an SDS request,
// and finally verifies the response from sds.NewResponse().
func TestGenerateSDS(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	certManager := tresorFake.NewFake(1 * time.Hour)

	// We deliberately set the namespace and service accounts to random values
	// to ensure no hard-coded values sneak in.
	proxySvcID := identity.New(uuid.New().String(), uuid.New().String())

	// This is the thing we are going to be requesting (pretending that the Envoy is requesting it)
	testCases := []struct {
		name                        string
		serviceIdentitiesForService map[service.MeshService][]identity.ServiceIdentity
		trustDomain                 string
		expectedCertToSAN           map[string][]string
	}{
		{
			name: "no identities",
			expectedCertToSAN: map[string][]string{
				secrets.NameForIdentity(proxySvcID): nil,
				secrets.NameForMTLSInbound:          nil,
			},
		},
		{
			name: "multiple outbound identities certs",
			serviceIdentitiesForService: map[service.MeshService][]identity.ServiceIdentity{
				{Name: "svc-1", Namespace: "ns-1"}: {
					identity.New("sa-1", "ns-1"),
					identity.New("sa-2", "ns-1"),
				},
				{Name: "svc-A", Namespace: "ns-A"}: {
					identity.New("sa-A", "ns-A"),
				},
			},
			expectedCertToSAN: map[string][]string{
				secrets.NameForUpstreamService("svc-1", "ns-1"): {
					"sa-1.ns-1.cluster.local",
					"sa-2.ns-1.cluster.local",
				},
				secrets.NameForUpstreamService("svc-A", "ns-A"): {
					"sa-A.ns-A.cluster.local",
				},
				secrets.NameForIdentity(proxySvcID): nil,
				secrets.NameForMTLSInbound:          nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := tassert.New(t)
			// The Common Name of the xDS Certificate (issued to the Envoy on the Pod by the Injector) will
			// have be prefixed with the ID of the pod. It is the first chunk of a dot-separated string.
			proxy := envoy.NewProxy(envoy.KindSidecar, uuid.New(), proxySvcID, nil, 1)
			meshCatalog := catalog.NewMockMeshCataloger(mockCtrl)

			var services []service.MeshService
			for svc, identities := range tc.serviceIdentitiesForService {
				services = append(services, svc)
				meshCatalog.EXPECT().ListServiceIdentitiesForService(svc).Return(identities)
			}
			meshCatalog.EXPECT().ListOutboundServicesForIdentity(proxy.Identity).Return(services)

			g := NewEnvoyConfigGenerator(meshCatalog, certManager, nil)
			// ----- Test with an properly configured proxy
			resources, err := g.generateSDS(context.Background(), proxy)
			assert.Equal(err, nil, fmt.Sprintf("Error evaluating sds.NewResponse(): %s", err))
			assert.NotNil(resources)
			var certNames, expectedCertNames []string

			// Collecting cert names for the assert has an easier to read print statement on failure, compared to
			// the assert.Equal statement or assert.Len, which will print either nothing or the entire cert object respectively.
			for name := range tc.expectedCertToSAN {
				expectedCertNames = append(expectedCertNames, name)
			}

			for _, resource := range resources {
				secret, ok := resource.(*xds_auth.Secret)
				assert.True(ok)
				certNames = append(certNames, secret.Name)

				assert.Contains(tc.expectedCertToSAN, secret.Name)
				if len(tc.expectedCertToSAN[secret.Name]) == 0 {
					continue // nothing more to do.
				}
				assert.Len(secret.GetValidationContext().MatchTypedSubjectAltNames, len(tc.expectedCertToSAN[secret.Name]))
				for _, matchers := range secret.GetValidationContext().MatchTypedSubjectAltNames {
					assert.Contains(tc.expectedCertToSAN[secret.Name], matchers.Matcher.GetExact())
				}
			}
			assert.ElementsMatch(expectedCertNames, certNames)
		})
	}
}

func TestGenerateLDS(t *testing.T) {
	assert := tassert.New(t)
	mockCtrl := gomock.NewController(t)
	mockMeshSpec := smi.NewMockMeshSpec(mockCtrl)

	stop := make(chan struct{})

	mockMeshSpec.EXPECT().ListTrafficTargets(gomock.Any()).Return([]*access.TrafficTarget{&tests.TrafficTarget, &tests.BookstoreV2TrafficTarget}).AnyTimes()
	mockMeshSpec.EXPECT().ListHTTPTrafficSpecs().Return([]*specs.HTTPRouteGroup{&tests.HTTPRouteGroup}).AnyTimes()
	mockMeshSpec.EXPECT().ListTrafficSplits(gomock.Any()).Return([]*split.TrafficSplit{}).AnyTimes()

	pod := tests.NewPodFixture(tests.Namespace, tests.BookbuyerServiceName, tests.BookbuyerServiceAccountName, map[string]string{
		constants.AppLabel:               tests.BookbuyerService.Name,
		constants.EnvoyUniqueIDLabelName: tests.ProxyUUID,
	})
	pod.Annotations = map[string]string{
		constants.PrometheusScrapeAnnotation: "true",
	}
	proxy := envoy.NewProxy(envoy.KindSidecar, uuid.MustParse(tests.ProxyUUID), identity.New(tests.BookbuyerServiceAccountName, tests.Namespace), nil, 1)
	provider := compute.NewMockInterface(mockCtrl)
	provider.EXPECT().ListEgressPoliciesForServiceAccount(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().GetIngressBackendPolicyForService(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().GetUpstreamTrafficSettingByService(gomock.Any()).Return(nil).AnyTimes()
	provider.EXPECT().GetUpstreamTrafficSettingByNamespace(gomock.Any()).Return(nil).AnyTimes()

	provider.EXPECT().GetServicesForServiceIdentity(tests.BookstoreServiceIdentity).Return([]service.MeshService{
		tests.BookstoreApexService,
		tests.BookstoreV1Service,
		tests.BookstoreV2Service,
	}).AnyTimes()
	provider.EXPECT().GetServicesForServiceIdentity(tests.BookstoreV2ServiceIdentity).Return([]service.MeshService{
		tests.BookstoreApexService,
		tests.BookstoreV2Service,
	}).AnyTimes()
	provider.EXPECT().GetResolvableEndpointsForService(gomock.Any()).Return([]endpoint.Endpoint{tests.Endpoint}).AnyTimes()
	provider.EXPECT().GetHostnamesForService(gomock.Any(), gomock.Any()).Return([]string{"dummy-hostname"}).AnyTimes()
	provider.EXPECT().IsMetricsEnabled(gomock.Any()).Return(true, nil).AnyTimes()
	provider.EXPECT().GetMeshConfig().Return(configv1alpha2.MeshConfig{
		Spec: configv1alpha2.MeshConfigSpec{
			Traffic: configv1alpha2.TrafficSpec{
				EnablePermissiveTrafficPolicyMode: false,
				EnableEgress:                      true,
			},
			Observability: configv1alpha2.ObservabilitySpec{
				Tracing: configv1alpha2.TracingSpec{
					Enable: false,
				},
			},
			FeatureFlags: configv1alpha2.FeatureFlags{
				EnableEgressPolicy: true,
			},
		},
	}).AnyTimes()
	provider.EXPECT().ListServicesForProxy(proxy).Return([]service.MeshService{tests.BookbuyerService}, nil).AnyTimes()

	meshCatalog := catalog.NewMeshCatalog(
		mockMeshSpec,
		tresorFake.NewFake(time.Hour),
		stop,
		provider,
		messaging.NewBroker(stop),
	)

	cm := tresorFake.NewFake(1 * time.Hour)
	g := NewEnvoyConfigGenerator(meshCatalog, cm, nil)
	resources, err := g.generateLDS(context.Background(), proxy)
	assert.Empty(err)
	assert.NotNil(resources)
	// There are 3 listeners configured based on the configuration:
	// 1. Outbound listener (outbound-listener)
	// 2. inbound listener (inbound-listener)
	// 3. Prometheus listener (inbound-prometheus-listener)
	assert.Len(resources, 3)

	// validating outbound listener
	listener, ok := resources[0].(*xds_listener.Listener)
	assert.True(ok)
	assert.Equal(listener.Name, lds.OutboundListenerName)
	assert.Equal(listener.TrafficDirection, xds_core.TrafficDirection_OUTBOUND)
	assert.Len(listener.ListenerFilters, 3) // Test has egress policy feature enabled, so 3 filters are expected: OriginalDst, TlsInspector, HttpInspector
	assert.Equal(envoy.OriginalDstFilterName, listener.ListenerFilters[0].Name)
	assert.NotNil(listener.FilterChains)
	// There are 3 filter chains configured on the outbound-listener based on the configuration:
	// 1. Filter chain for bookstore-v1
	// 2. Filter chain for bookstore-v2
	// 3. Filter chain for bookstore-apex due to TrafficSplit being configured
	expectedServiceFilterChainNames := []string{"outbound_default/bookstore-v1_8888_http", "outbound_default/bookstore-v2_8888_http", "outbound_default/bookstore-apex_8888_http"}
	var actualServiceFilterChainNames []string
	for _, fc := range listener.FilterChains {
		actualServiceFilterChainNames = append(actualServiceFilterChainNames, fc.Name)
	}
	assert.ElementsMatch(expectedServiceFilterChainNames, actualServiceFilterChainNames)
	assert.Len(listener.FilterChains, 3)
	assert.NotNil(listener.DefaultFilterChain)
	assert.Equal(listener.DefaultFilterChain.Name, lds.OutboundEgressFilterChainName)
	assert.Equal(listener.DefaultFilterChain.Filters[0].Name, envoy.TCPProxyFilterName)

	// validating inbound listener
	listener, ok = resources[1].(*xds_listener.Listener)
	assert.True(ok)
	assert.Equal(listener.Name, lds.InboundListenerName)
	assert.Equal(listener.TrafficDirection, xds_core.TrafficDirection_INBOUND)
	assert.Len(listener.ListenerFilters, 2)
	assert.Equal(listener.ListenerFilters[0].Name, envoy.TLSInspectorFilterName)
	assert.Equal(listener.ListenerFilters[1].Name, envoy.OriginalDstFilterName)
	assert.NotNil(listener.FilterChains)
	// There is 1 filter chains configured on the inbound-listner based on the configuration:
	// 1. Filter chanin for bookbuyer
	assert.Len(listener.FilterChains, 1)

	// validating prometheus listener
	listener, ok = resources[2].(*xds_listener.Listener)
	assert.True(ok)
	assert.Equal(listener.Name, lds.PrometheusListenerName)
	assert.Equal(listener.TrafficDirection, xds_core.TrafficDirection_INBOUND)
	assert.NotNil(listener.FilterChains)
	assert.Len(listener.FilterChains, 1)
}
