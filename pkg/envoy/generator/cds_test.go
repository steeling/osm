package generator

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	access "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/access/v1alpha3"
	split "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/split/v1alpha2"

	xds_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	xds_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	xds_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	xds_auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	tassert "github.com/stretchr/testify/assert"
	trequire "github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"

	configv1alpha2 "github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	"github.com/openservicemesh/osm/pkg/catalog"
	tresorFake "github.com/openservicemesh/osm/pkg/certificate/providers/tresor/fake"
	"github.com/openservicemesh/osm/pkg/compute"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/generator/cds"
	"github.com/openservicemesh/osm/pkg/envoy/secrets"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/models"
	"github.com/openservicemesh/osm/pkg/service"
	"github.com/openservicemesh/osm/pkg/tests"
	"github.com/openservicemesh/osm/pkg/trafficpolicy"
)

func TestGenerateCDS(t *testing.T) {
	assert := tassert.New(t)
	require := trequire.New(t)

	mockCtrl := gomock.NewController(t)
	kubeClient := testclient.NewSimpleClientset()
	mock := compute.NewMockInterface(mockCtrl)
	stop := make(chan struct{})
	meshCatalog := catalog.NewMeshCatalog(
		mock,
		tresorFake.NewFake(time.Hour),
		stop,
		messaging.NewBroker(stop),
	)

	proxyUUID := uuid.New()
	proxy := models.NewProxy(models.KindSidecar, proxyUUID, identity.New(tests.BookbuyerServiceAccountName, tests.Namespace), nil, 1)

	testMeshSvc := service.MeshService{
		Namespace:  tests.BookbuyerService.Namespace,
		Name:       tests.BookbuyerService.Name,
		Port:       80,
		TargetPort: 8080,
	}

	meshConfig := configv1alpha2.MeshConfig{
		Spec: configv1alpha2.MeshConfigSpec{
			Traffic: configv1alpha2.TrafficSpec{
				EnableEgress: true,
			},
			Observability: configv1alpha2.ObservabilitySpec{
				Tracing: configv1alpha2.TracingSpec{
					Enable: true,
				},
			},
			Sidecar: configv1alpha2.SidecarSpec{
				TLSMinProtocolVersion: "TLSv1_2",
				TLSMaxProtocolVersion: "TLSv1_3",
			},
		},
	}

	mock.EXPECT().IsMetricsEnabled(proxy).Return(true, nil).AnyTimes()
	mock.EXPECT().GetMeshConfig().Return(meshConfig).AnyTimes()
	mock.EXPECT().ListServicesForProxy(proxy).Return([]service.MeshService{testMeshSvc}, nil).AnyTimes()
	mock.EXPECT().ListTrafficSplits().Return(
		[]*split.TrafficSplit{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "bar",
				}},
		})
	mock.EXPECT().ListTrafficTargets().Return([]*access.TrafficTarget{&tests.TrafficTarget, &tests.BookstoreV2TrafficTarget}).AnyTimes()
	mock.EXPECT().GetServicesForServiceIdentity(gomock.Any()).Return([]service.MeshService{
		tests.BookstoreV1Service, tests.BookstoreV2Service,
	}).AnyTimes()
	mock.EXPECT().GetUpstreamTrafficSettingByService(gomock.Any()).Return(nil).AnyTimes()

	podlabels := map[string]string{
		constants.AppLabel:               testMeshSvc.Name,
		constants.EnvoyUniqueIDLabelName: proxyUUID.String(),
	}

	newPod1 := tests.NewPodFixture(tests.Namespace, fmt.Sprintf("pod-1-%s", proxyUUID), tests.BookbuyerServiceAccountName, podlabels)
	newPod1.Annotations = map[string]string{
		constants.PrometheusScrapeAnnotation: "true",
	}
	_, err := kubeClient.CoreV1().Pods(tests.Namespace).Create(context.TODO(), newPod1, metav1.CreateOptions{})
	assert.Nil(err)

	g := NewEnvoyConfigGenerator(meshCatalog, nil)

	resources, err := g.generateCDS(context.Background(), proxy)
	assert.Nil(err)

	// There are to any.Any resources in the ClusterDiscoveryStruct (Clusters)
	// There are 5 types of clusters that can exist based on the configuration:
	// 1. Destination cluster (Bookstore-v1, Bookstore-v2)
	// 2. Source cluster (Bookbuyer)
	// 3. Prometheus cluster
	// 4. Tracing cluster
	// 5. Passthrough cluster for egress
	numExpectedClusters := 6 // source and destination clusters
	assert.Equal(numExpectedClusters, len(resources))
	var actualClusters []*xds_cluster.Cluster
	for idx := range resources {
		cl, ok := resources[idx].(*xds_cluster.Cluster)
		require.True(ok)
		actualClusters = append(actualClusters, cl)
	}

	typedHTTPProtocolOptions, err := cds.GetTypedHTTPProtocolOptions(cds.GetHTTPProtocolOptions(""))
	assert.Nil(err)

	expectedLocalCluster := &xds_cluster.Cluster{
		TransportSocketMatches:        nil,
		Name:                          "default/bookbuyer|8080|local",
		AltStatName:                   "default/bookbuyer|8080|local",
		ClusterDiscoveryType:          &xds_cluster.Cluster_Type{Type: xds_cluster.Cluster_STRICT_DNS},
		EdsClusterConfig:              nil,
		RespectDnsTtl:                 true,
		DnsLookupFamily:               xds_cluster.Cluster_V4_ONLY,
		TypedExtensionProtocolOptions: typedHTTPProtocolOptions,
		LoadAssignment: &xds_endpoint.ClusterLoadAssignment{
			ClusterName: "default/bookbuyer|8080|local",
			Endpoints: []*xds_endpoint.LocalityLbEndpoints{
				{
					Locality: &xds_core.Locality{
						Zone: "zone",
					},
					LbEndpoints: []*xds_endpoint.LbEndpoint{{
						HostIdentifier: &xds_endpoint.LbEndpoint_Endpoint{
							Endpoint: &xds_endpoint.Endpoint{
								Address: &xds_core.Address{
									Address: &xds_core.Address_SocketAddress{
										SocketAddress: &xds_core.SocketAddress{
											Protocol: xds_core.SocketAddress_TCP,
											Address:  constants.LocalhostIPAddress,
											PortSpecifier: &xds_core.SocketAddress_PortValue{
												PortValue: uint32(8080),
											},
										},
									},
								},
							},
						},
						LoadBalancingWeight: &wrappers.UInt32Value{
							Value: constants.ClusterWeightAcceptAll,
						},
					}},
				},
			},
		},
	}

	upstreamTLSProto, err := anypb.New(envoy.GetUpstreamTLSContext(tests.BookbuyerServiceIdentity, tests.BookstoreV1Service, meshConfig.Spec.Sidecar))
	require.Nil(err)

	expectedBookstoreV1Cluster := &xds_cluster.Cluster{
		TransportSocketMatches:        nil,
		Name:                          "default/bookstore-v1|8888",
		AltStatName:                   "",
		ClusterDiscoveryType:          &xds_cluster.Cluster_Type{Type: xds_cluster.Cluster_EDS},
		TypedExtensionProtocolOptions: typedHTTPProtocolOptions,
		EdsClusterConfig: &xds_cluster.Cluster_EdsClusterConfig{
			EdsConfig: &xds_core.ConfigSource{
				ConfigSourceSpecifier: &xds_core.ConfigSource_Ads{
					Ads: &xds_core.AggregatedConfigSource{},
				},
				ResourceApiVersion: xds_core.ApiVersion_V3,
			},
			ServiceName: "",
		},
		TransportSocket: &xds_core.TransportSocket{
			Name: "default/bookstore-v1|8888",
			ConfigType: &xds_core.TransportSocket_TypedConfig{
				TypedConfig: &any.Any{
					TypeUrl: string(envoy.TypeUpstreamTLSContext),
					Value:   upstreamTLSProto.Value,
				},
			},
		},
		CircuitBreakers: &xds_cluster.CircuitBreakers{
			Thresholds: []*xds_cluster.CircuitBreakers_Thresholds{cds.GetDefaultCircuitBreakerThreshold()},
		},
	}

	upstreamTLSProto, err = anypb.New(envoy.GetUpstreamTLSContext(tests.BookbuyerServiceIdentity, tests.BookstoreV2Service, meshConfig.Spec.Sidecar))
	require.Nil(err)
	expectedBookstoreV2Cluster := &xds_cluster.Cluster{
		TransportSocketMatches:        nil,
		Name:                          "default/bookstore-v2|8888",
		AltStatName:                   "",
		ClusterDiscoveryType:          &xds_cluster.Cluster_Type{Type: xds_cluster.Cluster_EDS},
		TypedExtensionProtocolOptions: typedHTTPProtocolOptions,
		EdsClusterConfig: &xds_cluster.Cluster_EdsClusterConfig{
			EdsConfig: &xds_core.ConfigSource{
				ConfigSourceSpecifier: &xds_core.ConfigSource_Ads{
					Ads: &xds_core.AggregatedConfigSource{},
				},
				ResourceApiVersion: xds_core.ApiVersion_V3,
			},
			ServiceName: "",
		},
		TransportSocket: &xds_core.TransportSocket{
			Name: "default/bookstore-v2|8888",
			ConfigType: &xds_core.TransportSocket_TypedConfig{
				TypedConfig: &any.Any{
					TypeUrl: string(envoy.TypeUpstreamTLSContext),
					Value:   upstreamTLSProto.Value,
				},
			},
		},
		CircuitBreakers: &xds_cluster.CircuitBreakers{
			Thresholds: []*xds_cluster.CircuitBreakers_Thresholds{cds.GetDefaultCircuitBreakerThreshold()},
		},
	}

	expectedBookstoreV1TLSContext := xds_auth.UpstreamTlsContext{
		CommonTlsContext: &xds_auth.CommonTlsContext{
			TlsParams: &xds_auth.TlsParameters{
				TlsMinimumProtocolVersion: 3,
				TlsMaximumProtocolVersion: 4,
			},
			TlsCertificates: nil,
			TlsCertificateSdsSecretConfigs: []*xds_auth.SdsSecretConfig{{
				Name: "service-cert:default/bookstore-v1",
				SdsConfig: &xds_core.ConfigSource{
					ConfigSourceSpecifier: &xds_core.ConfigSource_Ads{
						Ads: &xds_core.AggregatedConfigSource{},
					},
				},
			}},
			ValidationContextType: &xds_auth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &xds_auth.SdsSecretConfig{
					Name: secrets.NameForUpstreamService(tests.BookstoreV1Service.Name, "default"),
					SdsConfig: &xds_core.ConfigSource{
						ConfigSourceSpecifier: &xds_core.ConfigSource_Ads{
							Ads: &xds_core.AggregatedConfigSource{},
						},
					},
				},
			},
			AlpnProtocols: envoy.ALPNInMesh,
		},
	}

	expectedBookstoreV2TLSContext := xds_auth.UpstreamTlsContext{
		CommonTlsContext: &xds_auth.CommonTlsContext{
			TlsParams: &xds_auth.TlsParameters{
				TlsMinimumProtocolVersion: 3,
				TlsMaximumProtocolVersion: 4,
			},
			TlsCertificates: nil,
			TlsCertificateSdsSecretConfigs: []*xds_auth.SdsSecretConfig{{
				Name: "service-cert:default/bookstore-v2",
				SdsConfig: &xds_core.ConfigSource{
					ConfigSourceSpecifier: &xds_core.ConfigSource_Ads{
						Ads: &xds_core.AggregatedConfigSource{},
					},
				},
			}},
			ValidationContextType: &xds_auth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &xds_auth.SdsSecretConfig{
					Name: secrets.NameForUpstreamService(tests.BookstoreV2Service.Name, "default"),
					SdsConfig: &xds_core.ConfigSource{
						ConfigSourceSpecifier: &xds_core.ConfigSource_Ads{
							Ads: &xds_core.AggregatedConfigSource{},
						},
					},
				},
			},
			AlpnProtocols: envoy.ALPNInMesh,
		},
	}

	expectedPrometheusCluster := &xds_cluster.Cluster{
		TransportSocketMatches: nil,
		Name:                   constants.EnvoyMetricsCluster,
		AltStatName:            constants.EnvoyMetricsCluster,
		ClusterDiscoveryType:   &xds_cluster.Cluster_Type{Type: xds_cluster.Cluster_STATIC},
		EdsClusterConfig:       nil,
		LoadAssignment: &xds_endpoint.ClusterLoadAssignment{
			ClusterName: constants.EnvoyMetricsCluster,
			Endpoints: []*xds_endpoint.LocalityLbEndpoints{
				{
					Locality: nil,
					LbEndpoints: []*xds_endpoint.LbEndpoint{{
						HostIdentifier: &xds_endpoint.LbEndpoint_Endpoint{
							Endpoint: &xds_endpoint.Endpoint{
								Address: &xds_core.Address{
									Address: &xds_core.Address_SocketAddress{
										SocketAddress: &xds_core.SocketAddress{
											Protocol: xds_core.SocketAddress_TCP,
											Address:  "127.0.0.1",
											PortSpecifier: &xds_core.SocketAddress_PortValue{
												PortValue: uint32(15000),
											},
										},
									},
								},
							},
						},
						LoadBalancingWeight: &wrappers.UInt32Value{
							Value: 100,
						},
					}},
				},
			},
		},
	}

	expectedClusters := []string{
		"default/bookstore-v1|8888",
		"default/bookstore-v2|8888",
		"default/bookbuyer|8080|local",
		"passthrough-outbound",
		"envoy-metrics-cluster",
		"envoy-tracing-cluster",
	}

	var foundClusters []string

	for _, a := range actualClusters {
		if a.Name == "default/bookbuyer|8080|local" {
			assert.Truef(cmp.Equal(expectedLocalCluster, a, protocmp.Transform()), cmp.Diff(expectedLocalCluster, a, protocmp.Transform()))
			foundClusters = append(foundClusters, "default/bookbuyer|8080|local")
			continue
		}
		if a.Name == "default/bookstore-v1|8888" {
			assert.Truef(cmp.Equal(expectedBookstoreV1Cluster, a, protocmp.Transform()), cmp.Diff(expectedBookstoreV1Cluster, a, protocmp.Transform()))

			upstreamTLSContext := xds_auth.UpstreamTlsContext{}
			err = a.TransportSocket.GetTypedConfig().UnmarshalTo(&upstreamTLSContext)
			require.Nil(err)

			assert.Equal(expectedBookstoreV1TLSContext.CommonTlsContext.TlsParams, upstreamTLSContext.CommonTlsContext.TlsParams)
			assert.Equal("bookstore-v1.default.svc.cluster.local", upstreamTLSContext.Sni)
			assert.Nil(a.LoadAssignment) //ClusterLoadAssignment setting for non EDS clusters

			foundClusters = append(foundClusters, "default/bookstore-v1|8888")
			continue
		}

		if a.Name == "default/bookstore-v2|8888" {
			assert.Truef(cmp.Equal(expectedBookstoreV2Cluster, a, protocmp.Transform()), cmp.Diff(expectedBookstoreV1Cluster, a, protocmp.Transform()))

			upstreamTLSContext := xds_auth.UpstreamTlsContext{}
			err = a.TransportSocket.GetTypedConfig().UnmarshalTo(&upstreamTLSContext)
			require.Nil(err)

			assert.Equal(expectedBookstoreV2TLSContext.CommonTlsContext.TlsParams, upstreamTLSContext.CommonTlsContext.TlsParams)
			assert.Equal("bookstore-v2.default.svc.cluster.local", upstreamTLSContext.Sni)
			assert.Nil(a.LoadAssignment) //ClusterLoadAssignment setting for non EDS clusters

			foundClusters = append(foundClusters, "default/bookstore-v2|8888")
			continue
		}

		if a.Name == constants.EnvoyMetricsCluster {
			assert.Truef(cmp.Equal(expectedPrometheusCluster, a, protocmp.Transform()), cmp.Diff(expectedPrometheusCluster, a, protocmp.Transform()))

			foundClusters = append(foundClusters, constants.EnvoyMetricsCluster)
			continue
		}

		if a.Name == constants.EnvoyTracingCluster {
			foundClusters = append(foundClusters, constants.EnvoyTracingCluster)
			continue
		}

		if a.Name == envoy.OutboundPassthroughCluster {
			foundClusters = append(foundClusters, envoy.OutboundPassthroughCluster)
			continue
		}
	}
	assert.ElementsMatch(expectedClusters, foundClusters)
}

func TestNewResponseListServicesError(t *testing.T) {
	proxy := models.NewProxy(models.KindSidecar, uuid.New(), identity.New(tests.BookbuyerServiceAccountName, tests.Namespace), nil, 1)

	ctrl := gomock.NewController(t)
	mock := compute.NewMockInterface(ctrl)
	stop := make(chan struct{})
	meshCatalog := catalog.NewMeshCatalog(
		mock,
		tresorFake.NewFake(time.Hour),
		stop,
		messaging.NewBroker(stop),
	)

	meshConfig := configv1alpha2.MeshConfig{
		Spec: configv1alpha2.MeshConfigSpec{
			Traffic: configv1alpha2.TrafficSpec{
				EnableEgress: true,
			},
			Observability: configv1alpha2.ObservabilitySpec{
				Tracing: configv1alpha2.TracingSpec{
					Enable: true,
				},
			},
			Sidecar: configv1alpha2.SidecarSpec{
				TLSMinProtocolVersion: "TLSv1_2",
				TLSMaxProtocolVersion: "TLSv1_3",
			},
		},
	}
	mock.EXPECT().GetMeshConfig().Return(meshConfig).AnyTimes()
	mock.EXPECT().ListTrafficTargets().Return([]*access.TrafficTarget{&tests.TrafficTarget, &tests.BookstoreV2TrafficTarget}).AnyTimes()
	mock.EXPECT().GetServicesForServiceIdentity(gomock.Any()).Return([]service.MeshService{
		tests.BookstoreV1Service, tests.BookstoreV2Service,
	}).AnyTimes()
	mock.EXPECT().GetUpstreamTrafficSettingByService(gomock.Any()).Return(nil).AnyTimes()
	mock.EXPECT().ListServicesForProxy(proxy).Return(nil, errors.New("no services found")).AnyTimes()

	g := NewEnvoyConfigGenerator(meshCatalog, nil)

	resources, err := g.generateCDS(context.Background(), proxy)
	tassert.Error(t, err)
	tassert.Nil(t, resources)
}

func TestNewResponseGetEgressClusterConfigsError(t *testing.T) {
	proxyIdentity := identity.K8sServiceAccount{Name: "svcacc", Namespace: "ns"}.ToServiceIdentity()
	proxyUUID := uuid.New()
	proxy := models.NewProxy(models.KindSidecar, proxyUUID, identity.New("svcacc", "ns"), nil, 1)

	ctrl := gomock.NewController(t)
	meshCatalog := catalog.NewMockMeshCataloger(ctrl)

	meshCatalog.EXPECT().GetInboundMeshClusterConfigs(gomock.Any()).Return(nil).Times(1)
	meshCatalog.EXPECT().GetOutboundMeshClusterConfigs(proxyIdentity).Return(nil).Times(1)
	meshCatalog.EXPECT().GetEgressClusterConfigs(proxyIdentity).Return(nil, fmt.Errorf("some error")).Times(1)
	meshCatalog.EXPECT().IsMetricsEnabled(proxy).Return(false, nil).AnyTimes()
	meshCatalog.EXPECT().GetMeshConfig().AnyTimes()
	meshCatalog.EXPECT().ListServicesForProxy(proxy).Return(nil, nil).AnyTimes()

	g := NewEnvoyConfigGenerator(meshCatalog, nil)

	resources, err := g.generateCDS(context.Background(), proxy)
	tassert.NoError(t, err)
	tassert.Empty(t, resources)
}

func TestNewResponseGetEgressTrafficPolicyNotEmpty(t *testing.T) {
	proxyIdentity := identity.K8sServiceAccount{Name: "svcacc", Namespace: "ns"}.ToServiceIdentity()
	proxyUUID := uuid.New()
	proxy := models.NewProxy(models.KindSidecar, proxyUUID, identity.New("svcacc", "ns"), nil, 1)

	ctrl := gomock.NewController(t)
	meshCatalog := catalog.NewMockMeshCataloger(ctrl)
	meshCatalog.EXPECT().GetInboundMeshClusterConfigs(gomock.Any()).Return(nil).Times(1)
	meshCatalog.EXPECT().GetOutboundMeshClusterConfigs(proxyIdentity).Return(nil).Times(1)
	meshCatalog.EXPECT().IsMetricsEnabled(proxy).Return(false, nil).AnyTimes()
	meshCatalog.EXPECT().GetEgressClusterConfigs(proxyIdentity).Return([]*trafficpolicy.EgressClusterConfig{
		{Name: "my-cluster"},
		{Name: "my-cluster"}, // the test ensures this duplicate is removed
	}, nil).Times(1)
	meshCatalog.EXPECT().GetMeshConfig().AnyTimes()
	meshCatalog.EXPECT().ListServicesForProxy(proxy).Return(nil, nil).AnyTimes()

	g := NewEnvoyConfigGenerator(meshCatalog, nil)

	resources, err := g.generateCDS(context.Background(), proxy)
	tassert.NoError(t, err)
	tassert.Len(t, resources, 1)
	tassert.Equal(t, resources[0].(*xds_cluster.Cluster).Name, "my-cluster")
}
