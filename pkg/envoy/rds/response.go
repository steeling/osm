package rds

import (
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/rds/route"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/trafficpolicy"
)

// NewResponse creates a new Route Discovery Response.
func NewResponse(cataloger catalog.MeshCataloger, proxy *envoy.Proxy, cm *certificate.Manager, _ *registry.ProxyRegistry) ([]types.Resource, error) {
	proxyServices, err := cataloger.ListServicesForProxy(proxy)
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrFetchingServiceList)).
			Msgf("Error looking up services for Envoy with name=%s", proxy.GetName())
		return nil, err
	}
	var rdsResources []types.Resource

	trustDomain := cm.GetTrustDomain()

	// ---
	// Build inbound mesh route configurations. These route configurations allow
	// the services associated with this proxy to accept traffic from downstream
	// clients on allowed routes.
	inboundMeshTrafficPolicy := cataloger.GetInboundMeshTrafficPolicy(proxy.Identity, proxyServices)
	if inboundMeshTrafficPolicy != nil {
		inboundMeshRouteConfig := route.BuildInboundMeshRouteConfiguration(inboundMeshTrafficPolicy.HTTPRouteConfigsPerPort, proxy, cataloger.GetMeshConfig().Spec.FeatureFlags.EnableWASMStats, trustDomain)
		for _, config := range inboundMeshRouteConfig {
			rdsResources = append(rdsResources, config)
		}
	}

	// ---
	// Build outbound mesh route configurations. These route configurations allow this proxy
	// to direct traffic to upstream services that it is authorized to connect to on allowed
	// routes.
	outboundMeshTrafficPolicy := cataloger.GetOutboundMeshTrafficPolicy(proxy.Identity)

	if outboundMeshTrafficPolicy != nil {
		outboundMeshRouteConfig := route.BuildOutboundMeshRouteConfiguration(outboundMeshTrafficPolicy.HTTPRouteConfigsPerPort)
		for _, config := range outboundMeshRouteConfig {
			rdsResources = append(rdsResources, config)
		}
	}

	// ---
	// Build ingress route configurations. These route configurations allow the
	// services associated with this proxy to accept ingress traffic from downstream
	// clients on allowed routes.
	var ingressTrafficPolicies []*trafficpolicy.InboundTrafficPolicy
	for _, svc := range proxyServices {
		ingressPolicy, err := cataloger.GetIngressTrafficPolicy(svc)
		if err != nil {
			log.Error().Err(err).Msgf("Error getting ingress traffic policy for service %s, skipping", svc)
			continue
		}
		if ingressPolicy == nil {
			log.Trace().Msgf("No ingress policy configured for service %s", svc)
			continue
		}
		ingressTrafficPolicies = trafficpolicy.MergeInboundPolicies(ingressTrafficPolicies, ingressPolicy.HTTPRoutePolicies...)
	}
	if len(ingressTrafficPolicies) > 0 {
		ingressRouteConfig := route.BuildIngressConfiguration(ingressTrafficPolicies, trustDomain)
		rdsResources = append(rdsResources, ingressRouteConfig)
	}

	// ---
	// Build egress route configurations. These route configurations allow this
	// proxy to direct traffic to external non-mesh destinations on allowed routes.
	egressTrafficPolicy, err := cataloger.GetEgressTrafficPolicy(proxy.Identity)
	if err != nil {
		log.Error().Err(err).Msgf("Error retrieving egress traffic policies for proxy with identity %s, skipping egress route configuration", proxy.Identity)
	}
	if egressTrafficPolicy != nil {
		egressRouteConfigs := route.BuildEgressRouteConfiguration(egressTrafficPolicy.HTTPRouteConfigsPerPort)
		for _, egressConfig := range egressRouteConfigs {
			rdsResources = append(rdsResources, egressConfig)
		}
	}

	return rdsResources, nil
}
