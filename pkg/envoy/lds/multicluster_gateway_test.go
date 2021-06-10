package lds

import (
	"fmt"
	"testing"

	xds_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/mock/gomock"
	tassert "github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openservicemesh/osm/pkg/auth"
	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/rds/route"
	"github.com/openservicemesh/osm/pkg/service"
	"github.com/openservicemesh/osm/pkg/tests"
)

var (
	bookstoreSvc     = service.MeshService{Namespace: "bookstore", Name: "bookstore-v1", Cluster: "local"}
	bookwarehouseSvc = service.MeshService{Namespace: "bookwarehouse", Name: "bookwarehouse", Cluster: "local"}
)

func TestNewMultiClusterGatewayListener(t *testing.T) {
	assert := tassert.New(t)
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockCatalog := catalog.NewMockMeshCataloger(mockCtrl)
	mockConfigurator := configurator.NewMockConfigurator(mockCtrl)

	// Mock calls used to build the HTTP connection manager
	mockConfigurator.EXPECT().IsTracingEnabled().Return(false).AnyTimes()
	mockConfigurator.EXPECT().GetTracingEndpoint().Return("test-api").AnyTimes()
	mockConfigurator.EXPECT().GetInboundExternalAuthConfig().Return(auth.ExtAuthConfig{
		Enable: false,
	}).AnyTimes()
	mockCatalog.EXPECT().GetWeightedClustersForUpstream(bookstoreSvc).AnyTimes()
	mockCatalog.EXPECT().GetWeightedClustersForUpstream(bookwarehouseSvc).AnyTimes()

	lb := &listenerBuilder{
		meshCatalog: mockCatalog,
		cfg:         mockConfigurator,
		// let's pretend the bookbuyer can reach out to the warehouse over TCP, the bookstore-v1 on 2 different ports
		// over http.
		serviceIdentity: tests.BookbuyerServiceIdentity,
	}

	// GetServiceHostnames
	mockCatalog.EXPECT().ListMeshServicesForIdentity(lb.serviceIdentity).Return([]service.MeshService{
		bookstoreSvc,
		bookwarehouseSvc,
		// These should not affect the gateway.
		{Namespace: "bookwarehouse", Name: "bookwarehouse", Cluster: "remote-y"},
		{Namespace: "bookwarehouse", Name: "bookwarehouse", Cluster: "global"},
	}).AnyTimes()

	mockCatalog.EXPECT().GetServiceHostnames(
		service.MeshService{
			Namespace: "bookstore",
			Name:      "bookstore-v1",
			Cluster:   "local"}, service.RemoteCluster).Return(
		[]string{
			"bookstore-v1.bookstore.svc.cluster.cluster-x",
			"bookstore-v1.bookstore.svc.cluster.global",
		}, nil).AnyTimes()

	mockCatalog.EXPECT().GetServiceHostnames(
		service.MeshService{
			Namespace: "bookwarehouse",
			Name:      "bookwarehouse",
			Cluster:   "local"}, service.RemoteCluster).Return(
		[]string{
			"bookwarehouse.bookwarehouse.svc.cluster.cluster-x",
			"bookwarehouse.bookwarehouse.svc.cluster.global",
		}, nil).AnyTimes()

	mockCatalog.EXPECT().GetPortToProtocolMappingForService(bookstoreSvc).Return(
		map[uint32]string{8080: constants.ProtocolHTTP, 8081: constants.ProtocolTCP}, nil).AnyTimes()

	mockCatalog.EXPECT().GetPortToProtocolMappingForService(bookwarehouseSvc).Return(
		map[uint32]string{8082: constants.ProtocolHTTP}, nil).AnyTimes()

	httpFilter, err := lb.getOutboundHTTPFilter(route.OutboundRouteConfigName)
	assert.NoError(err)
	tcpFilter, err := lb.getOutboundTCPFilter(bookstoreSvc)
	assert.NoError(err)
	expectedListener := &xds_listener.Listener{
		Name:    multiclusterListenerName,
		Address: envoy.GetAddress(constants.WildcardIPAddr, constants.EnvoyInboundListenerPort),
		FilterChains: []*xds_listener.FilterChain{
			{
				Name:    fmt.Sprintf("%s:%s", outboundMeshHTTPFilterChainPrefix, bookstoreSvc),
				Filters: []*xds_listener.Filter{httpFilter}, // We're not testing the filter, which is mostly static.
				FilterChainMatch: &xds_listener.FilterChainMatch{
					DestinationPort: &wrapperspb.UInt32Value{
						Value: 8080,
					},
					ServerNames: []string{
						"bookstore-v1.bookstore.svc.cluster.cluster-x",
						"bookstore-v1.bookstore.svc.cluster.global",
					},
					ApplicationProtocols: httpProtocols,
				},
			},
			{
				Name:    fmt.Sprintf("%s:%s", outboundMeshTCPFilterChainPrefix, bookstoreSvc),
				Filters: []*xds_listener.Filter{tcpFilter}, // We're not testing the filter, which is mostly static.
				FilterChainMatch: &xds_listener.FilterChainMatch{
					DestinationPort: &wrapperspb.UInt32Value{
						Value: 8081,
					},
					ServerNames: []string{
						"bookstore-v1.bookstore.svc.cluster.cluster-x",
						"bookstore-v1.bookstore.svc.cluster.global",
					},
				},
			},
			{
				Name:    fmt.Sprintf("%s:%s", outboundMeshHTTPFilterChainPrefix, bookwarehouseSvc),
				Filters: []*xds_listener.Filter{httpFilter}, // We're not testing the filter, which is mostly static.
				FilterChainMatch: &xds_listener.FilterChainMatch{
					DestinationPort: &wrapperspb.UInt32Value{
						Value: 8082,
					},
					ServerNames: []string{
						"bookwarehouse.bookwarehouse.svc.cluster.cluster-x",
						"bookwarehouse.bookwarehouse.svc.cluster.global",
					},
					ApplicationProtocols: httpProtocols,
				},
			},
		},
		ListenerFilters: []*xds_listener.ListenerFilter{
			{
				Name: wellknown.OriginalDestination,
			},
		},
	}
	actualListener := lb.newMultiClusterGatewayListener()
	// Can't simply compare these types unfortunately.
	assert.Equal(len(expectedListener.FilterChains), len(actualListener.FilterChains))
	for i := range expectedListener.FilterChains {
		expectedFC := expectedListener.FilterChains[i]
		actualFC := expectedListener.FilterChains[i]

		assert.Equal(expectedFC.FilterChainMatch, actualFC.FilterChainMatch)
		assert.Len(expectedFC.Filters, len(actualFC.Filters))
		for i := range expectedFC.Filters {
			assert.Equal(expectedFC.Filters[i], actualFC.Filters[i])
		}
	}
}
