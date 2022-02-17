package xdsutils

// TODO(steeling): move xdsutils.go here as well.

import (
	"fmt"
	"strings"

	xds_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	xds_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/service"
	"github.com/openservicemesh/osm/pkg/trafficpolicy"
)

func OutboundHTTPFilter(routeConfigName string, statsHeaders map[string]string, tracingAPIEndpoints string, enableTracing bool) (*xds_listener.Filter, error) {
	var marshalledFilter *any.Any
	var err error

	// Build the HTTP connection manager filter from its options
	outboundConnManager, err := httpConnManagerOptions{
		direction:         outbound,
		rdsRoutConfigName: routeConfigName,

		// Additional filters
		wasmStatsHeaders: statsHeaders,
		extAuthConfig:    nil, // Ext auth is not configured for outbound connections

		// Tracing options
		enableTracing:      enableTracing,
		tracingAPIEndpoint: lb.cfg.GetTracingEndpoint(),
	}.build()
	if err != nil {
		return nil, errors.Wrapf(err, "Error building outbound HTTP connection manager for proxy identity %s", lb.serviceIdentity)
	}

	marshalledFilter, err = ptypes.MarshalAny(outboundConnManager)
	if err != nil {
		return nil, errors.Wrapf(err, "Error marshalling outbound HTTP connection manager for proxy identity %s", lb.serviceIdentity)
	}

	return &xds_listener.Filter{
		Name:       wellknown.HTTPConnectionManager,
		ConfigType: &xds_listener.Filter_TypedConfig{TypedConfig: marshalledFilter},
	}, nil
}

// TODO: put this on the trafficMatch Policy
func getOutboundFilterChainMatchForService(trafficMatch trafficpolicy.TrafficMatch) (*xds_listener.FilterChainMatch, error) {
	filterMatch := &xds_listener.FilterChainMatch{
		DestinationPort: &wrapperspb.UInt32Value{
			Value: uint32(trafficMatch.DestinationPort),
		},
	}

	if len(trafficMatch.DestinationIPRanges) == 0 {
		return nil, errors.Errorf("Destination IP ranges not specified for mesh upstream traffic match %s", trafficMatch.Name)
	}
	for _, ipRange := range trafficMatch.DestinationIPRanges {
		cidr, err := envoy.GetCIDRRangeFromStr(ipRange)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.ErrInvalidEgressIPRange.String()).
				Msgf("Error parsing IP range %s while building outbound mesh filter chain match %s, skipping", ipRange, trafficMatch.Name)
			continue
		}
		filterMatch.PrefixRanges = append(filterMatch.PrefixRanges, cidr)
	}

	return filterMatch, nil
}

func getOutboundTCPFilterChainForService(trafficMatch trafficpolicy.TrafficMatch) (*xds_listener.FilterChain, error) {
	// Get TCP filter for service
	filter, err := getOutboundTCPFilter(trafficMatch)
	if err != nil {
		log.Error().Err(err).Msgf("Error getting outbound TCP filter for traffic match %s", trafficMatch.Name)
		return nil, err
	}

	// Get filter match criteria for destination service
	filterChainMatch, err := getOutboundFilterChainMatchForService(trafficMatch)
	if err != nil {
		log.Error().Err(err).Msgf("Error getting HTTP filter chain match for traffic match %s", trafficMatch.Name)
		return nil, err
	}

	filterChainName := fmt.Sprintf("%s:%s", outboundMeshTCPFilterChainPrefix, trafficMatch.Name)
	return &xds_listener.FilterChain{
		Name:             filterChainName,
		Filters:          []*xds_listener.Filter{filter},
		FilterChainMatch: filterChainMatch,
	}, nil
}

func getOutboundTCPFilter(trafficMatch trafficpolicy.TrafficMatch) (*xds_listener.Filter, error) {
	tcpProxy := &xds_tcp_proxy.TcpProxy{
		StatPrefix: fmt.Sprintf("%s_%s", outboundMeshTCPProxyStatPrefix, trafficMatch.Name),
	}

	if len(trafficMatch.WeightedClusters) == 0 {
		return nil, errors.Errorf("At least 1 cluster must be configured for an upstream TCP service. None set for traffic match %s", trafficMatch.Name)
		// No weighted clusters implies a traffic split does not exist for this upstream, proxy it as is
	} else if len(trafficMatch.WeightedClusters) == 1 {
		tcpProxy.ClusterSpecifier = &xds_tcp_proxy.TcpProxy_Cluster{Cluster: trafficMatch.WeightedClusters[0].ClusterName.String()}
	} else {
		// Weighted clusters found for this upstream, proxy traffic meant for this upstream to its weighted clusters
		var clusterWeights []*xds_tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight
		for _, cluster := range trafficMatch.WeightedClusters {
			clusterWeights = append(clusterWeights, &xds_tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight{
				Name:   cluster.ClusterName.String(),
				Weight: uint32(cluster.Weight),
			})
		}
		tcpProxy.ClusterSpecifier = &xds_tcp_proxy.TcpProxy_WeightedClusters{
			WeightedClusters: &xds_tcp_proxy.TcpProxy_WeightedCluster{
				Clusters: clusterWeights,
			},
		}
	}

	marshalledTCPProxy, err := ptypes.MarshalAny(tcpProxy)
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
			Msgf("Error marshalling TcpProxy object needed by outbound TCP filter for traffic match %s", trafficMatch.Name)
		return nil, err
	}

	return &xds_listener.Filter{
		Name:       wellknown.TCPProxy,
		ConfigType: &xds_listener.Filter_TypedConfig{TypedConfig: marshalledTCPProxy},
	}, nil
}

// getOutboundFilterChainPerUpstream returns a list of filter chains corresponding to upstream services
func getOutboundFilterChainPerUpstream(outboundMeshTrafficPolicy *trafficpolicy.OutboundMeshTrafficPolicy) []*xds_listener.FilterChain {
	var filterChains []*xds_listener.FilterChain

	for _, trafficMatch := range outboundMeshTrafficPolicy.TrafficMatches {
		log.Trace().Msgf("Building outbound mesh filter chain %s for proxy with identity %s", trafficMatch.Name, lb.serviceIdentity)
		// Create an outbound filter chain match per TrafficMatch object
		switch strings.ToLower(trafficMatch.DestinationProtocol) {
		case constants.ProtocolHTTP, constants.ProtocolGRPC:
			// Construct HTTP filter chain
			if httpFilterChain, err := getOutboundHTTPFilterChainForService(*trafficMatch); err != nil {
				log.Error().Err(err).Msgf("Error constructing outbound HTTP filter chain for traffic match %s on proxy with identity %s", trafficMatch.Name, lb.serviceIdentity)
			} else {
				filterChains = append(filterChains, httpFilterChain)
			}

		case constants.ProtocolTCP, constants.ProtocolTCPServerFirst:
			// Construct TCP filter chain
			if tcpFilterChain, err := getOutboundTCPFilterChainForService(*trafficMatch); err != nil {
				log.Error().Err(err).Msgf("Error constructing outbound TCP filter chain for traffic match %s on proxy with identity %s", trafficMatch.Name, lb.serviceIdentity)
			} else {
				filterChains = append(filterChains, tcpFilterChain)
			}

		default:
			log.Error().Msgf("Cannot build outbound filter chain, unsupported protocol %s for traffic match %s", trafficMatch.DestinationProtocol, trafficMatch.Name)
		}
	}

	return filterChains
}

func getInboundTCPFilters(proxyService service.MeshService) ([]*xds_listener.Filter, error) {
	var filters []*xds_listener.Filter

	// Apply an RBAC filter when permissive mode is disabled. The RBAC filter must be the first filter in the list of filters.
	if !lb.cfg.IsPermissiveTrafficPolicyMode() {
		// Apply RBAC policies on the inbound filters based on configured policies
		rbacFilter, err := lb.buildRBACFilter()
		if err != nil {
			log.Error().Err(err).Msgf("Error applying RBAC filter for proxy service %s", proxyService)
			return nil, err
		}
		// RBAC filter should be the very first filter in the filter chain
		filters = append(filters, rbacFilter)
	}

	// Apply the TCP Proxy Filter
	tcpProxy := &xds_tcp_proxy.TcpProxy{
		StatPrefix:       fmt.Sprintf("%s.%s", inboundMeshTCPProxyStatPrefix, proxyService.EnvoyLocalClusterName()),
		ClusterSpecifier: &xds_tcp_proxy.TcpProxy_Cluster{Cluster: proxyService.EnvoyLocalClusterName()},
	}
	marshalledTCPProxy, err := ptypes.MarshalAny(tcpProxy)
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
			Msgf("Error marshalling TcpProxy object for egress HTTPS filter chain")
		return nil, err
	}
	tcpProxyFilter := &xds_listener.Filter{
		Name:       wellknown.TCPProxy,
		ConfigType: &xds_listener.Filter_TypedConfig{TypedConfig: marshalledTCPProxy},
	}
	filters = append(filters, tcpProxyFilter)

	return filters, nil
}
