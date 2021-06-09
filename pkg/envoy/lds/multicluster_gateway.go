package lds

import (
	"fmt"

	xds_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/rds/route"
	"github.com/openservicemesh/osm/pkg/service"
)

func (lb *listenerBuilder) newMultiClusterGatewayListener() (*xds_listener.Listener, error) {
	serviceFilterChains := lb.getMultiClusterGatewayFilterChainPerUpstream()

	listener := &xds_listener.Listener{
		Name:    multiclusterListenerName,
		Address: envoy.GetAddress(constants.WildcardIPAddr, constants.EnvoyInboundListenerPort),
		// TODO(steeling) for this to work on windows, there needs to be an inbound and an outbound listener
		// see: https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/original_dst_filter#config-listener-filters-original-dst
		// TrafficDirection: ...,
		FilterChains: serviceFilterChains,
		ListenerFilters: []*xds_listener.ListenerFilter{
			{
				// The OriginalDestination ListenerFilter is used to redirect traffic
				// to its original destination.
				Name: wellknown.OriginalDestination,
			},
		},
	}
	return listener, nil
}

func (lb *listenerBuilder) getMultiClusterGatewayFilterChainPerUpstream() []*xds_listener.FilterChain {
	var filterChains []*xds_listener.FilterChain

	dstServices := lb.meshCatalog.ListMeshServicesForIdentity(lb.serviceIdentity)
	if len(dstServices) == 0 {
		log.Debug().Msgf("Proxy with identity %s does not have any allowed upstream services", lb.serviceIdentity)
		return filterChains
	}

	// Iterate all destination services
	for _, upstream := range dstServices {
		// Filter out to only the local and global services.
		// TODO(steeling): local here needs to the remote name.
		if !upstream.Local() || !upstream.Global() {
			continue
		}

		log.Trace().Msgf("Building outbound filter chain for upstream service %s for proxy with identity %s", upstream, lb.serviceIdentity)
		protocolToPortMap, err := lb.meshCatalog.GetPortToProtocolMappingForService(upstream)
		if err != nil {
			log.Error().Err(err).Msgf("Error retrieving port to protocol mapping for upstream service %s", upstream)
			continue
		}

		// Create protocol specific inbound filter chains per port to handle different ports serving different protocols
		for port, appProtocol := range protocolToPortMap {
			if filterChain, err := lb.multiClusterGatewayFilterChainForService(upstream, port, appProtocol); err != nil {
				log.Error().Err(err).Msgf("Error constructing outbound HTTP filter chain for upstream service %s on proxy with identity %s", upstream, lb.serviceIdentity)
			} else {
				filterChains = append(filterChains, filterChain)
			}
		}
	}

	return filterChains
}

func (lb *listenerBuilder) multiClusterGatewayFilterChainForService(upstream service.MeshService, port uint32, protocol string) (*xds_listener.FilterChain, error) {
	var (
		filter *xds_listener.Filter
		name   string
		err    error
	)
	// We use the same filter as outbound for the multicluster gateway.
	if protocol == constants.ProtocolHTTP || protocol == constants.ProtocolGRPC {
		filter, err = lb.getOutboundHTTPFilter(route.OutboundRouteConfigName)
		name = fmt.Sprintf("%s:%s", outboundMeshHTTPFilterChainPrefix, upstream)
	} else if protocol == constants.ProtocolTCP {
		filter, err = lb.getOutboundTCPFilter(upstream)
		name = fmt.Sprintf("%s:%s", outboundMeshHTTPFilterChainPrefix, upstream)
	} else {
		return nil, fmt.Errorf("Cannot build outbound filter chain, unsupported protocol %s for upstream:port %s:%d", protocol, upstream, port)
	}

	if err != nil {
		log.Error().Err(err).Msgf("Error getting %s filter for upstream service %s", protocol, upstream)
		return nil, err
	}

	// TODO(steeling): I believe the regular http outbound filter could simply use this as well.
	// It would result in a lot of dead code that could be deleted.
	// In combination with the fact that I don't think EDS is used...
	hostnames, _ := lb.meshCatalog.GetMultiClusterGatewayHostnames(upstream)
	return &xds_listener.FilterChain{
		Name:    name,
		Filters: []*xds_listener.Filter{filter},
		FilterChainMatch: &xds_listener.FilterChainMatch{
			DestinationPort: &wrapperspb.UInt32Value{
				Value: port,
			},
			ServerNames:          hostnames, // TODO(steeling): this should only return non-local...
			ApplicationProtocols: httpProtocols,
		},
	}, nil
}
