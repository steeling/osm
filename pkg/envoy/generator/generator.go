package generator

import (
	"context"
	"fmt"
	"sync"
	"time"

	xds_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/rs/zerolog/log"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/endpoint"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/generator/eds"
	"github.com/openservicemesh/osm/pkg/envoy/generator/lds"
	"github.com/openservicemesh/osm/pkg/envoy/generator/sds"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/service"
	"github.com/openservicemesh/osm/pkg/utils"
)

type EnvoyConfigGenerator struct {
	catalog        catalog.MeshCataloger
	generators     map[envoy.TypeURI]func(context.Context, *envoy.Proxy) ([]types.Resource, error)
	certManager    *certificate.Manager
	proxyRegistry  *registry.ProxyRegistry
	xdsMapLogMutex sync.Mutex
	xdsLog         map[string]map[envoy.TypeURI][]time.Time
}

func NewEnvoyConfigGenerator(catalog catalog.MeshCataloger, certManager *certificate.Manager, proxyRegistry *registry.ProxyRegistry) *EnvoyConfigGenerator {
	g := &EnvoyConfigGenerator{
		catalog:       catalog,
		certManager:   certManager,
		proxyRegistry: proxyRegistry,
		xdsLog:        make(map[string]map[envoy.TypeURI][]time.Time),
	}
	// g.generators = map[envoy.TypeURI]func(context.Context, *envoy.Proxy) ([]types.Resource, error){
	// 	envoy.TypeCDS: g.generateClusterResponse,
	// 	envoy.TypeEDS: g.generateEndpointResponse,
	// 	envoy.TypeLDS: g.generateListenerResponse,
	// 	envoy.TypeRDS: g.generateRouteResponse,
	// 	envoy.TypeSDS: g.generateSecretResponse,
	// }
	return g
}

// GenerateResources generates and returns the resources for the given proxy.
func (g *EnvoyConfigGenerator) GenerateResources(ctx context.Context, proxy *envoy.Proxy) (map[string][]types.Resource, error) {
	cacheResourceMap := map[string][]types.Resource{}
	for typeURI, handler := range g.generators {
		log.Trace().Str("proxy", proxy.String()).Msgf("Getting resources for type %s", typeURI.Short())

		if g.catalog.GetMeshConfig().Spec.Observability.EnableDebugServer {
			g.trackXDSLog(proxy.GetName(), typeURI)
		}

		startedAt := time.Now()
		resources, err := handler(ctx, proxy)
		xdsPathTimeTrack(startedAt, typeURI, proxy, err == nil)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrGeneratingReqResource)).Str("proxy", proxy.String()).
				Msgf("Error generating response for typeURI: %s", typeURI.Short())
			xdsPathTimeTrack(time.Now(), envoy.TypeADS, proxy, false)
			return nil, err
		}

		cacheResourceMap[typeURI.String()] = resources
	}

	xdsPathTimeTrack(time.Now(), envoy.TypeADS, proxy, true)
	return cacheResourceMap, nil
}

// generateEDS creates a new Endpoint Discovery Response.
func (g *EnvoyConfigGenerator) generateEDS(ctx context.Context, proxy *envoy.Proxy) ([]types.Resource, error) {
	meshSvcEndpoints := make(map[service.MeshService][]endpoint.Endpoint)
	builder := eds.NewEDSBuilder()

	for _, dstSvc := range g.catalog.ListOutboundServicesForIdentity(proxy.Identity) {
		builder.AddEndpoints(
			dstSvc,
			g.catalog.ListAllowedUpstreamEndpointsForService(proxy.Identity, dstSvc),
		)

		log.Trace().Msgf("Allowed outbound service endpoints for proxy with identity %s: %v", proxy.Identity, meshSvcEndpoints)
	}

	return builder.Build(), nil
}

func (g *EnvoyConfigGenerator) generateSDS(ctx context.Context, proxy *envoy.Proxy) ([]types.Resource, error) {
	log.Info().Str("proxy", proxy.String()).Msg("Composing SDS Discovery Response")

	// sdsBuilder: builds the Secret Discovery Response
	builder := sds.NewBuilder().SetProxy(proxy).SetTrustDomain(g.certManager.GetTrustDomain())

	// 1. Issue a service certificate for this proxy
	cert, err := g.certManager.IssueCertificate(proxy.Identity.String(), certificate.Service)
	if err != nil {
		log.Error().Err(err).Str("proxy", proxy.String()).Msgf("Error issuing a certificate for proxy")
		return nil, err
	}
	builder.SetProxyCert(cert)

	// Set service identities for services in requests
	serviceIdentitiesForOutboundServices := make(map[service.MeshService][]identity.ServiceIdentity)

	for _, svc := range g.catalog.ListOutboundServicesForIdentity(proxy.Identity) {
		serviceIdentitiesForOutboundServices[svc] = g.catalog.ListServiceIdentitiesForService(svc)
	}

	builder.SetServiceIdentitiesForService(serviceIdentitiesForOutboundServices)

	// Get SDS Secret Resources based on requested certs in the DiscoveryRequest
	var sdsResources = make([]types.Resource, 0, len(serviceIdentitiesForOutboundServices)+2)
	for _, envoyProto := range builder.Build() {
		sdsResources = append(sdsResources, envoyProto)
	}
	return sdsResources, nil
}

// NewResponse creates a new Listener Discovery Response.
// The response build 3 Listeners:
// 1. Inbound listener to handle incoming traffic
// 2. Outbound listener to handle outgoing traffic
// 3. Prometheus listener for metrics
func (g *EnvoyConfigGenerator) generateLDS(ctx context.Context, proxy *envoy.Proxy) ([]types.Resource, error) {
	var ldsResources []types.Resource

	var statsHeaders map[string]string
	meshConfig := g.catalog.GetMeshConfig()

	if meshConfig.Spec.FeatureFlags.EnableWASMStats {
		statsHeaders = proxy.StatsHeaders()
	}

	svcList, err := g.catalog.ListServicesForProxy(proxy)
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrFetchingServiceList)).
			Str("proxy", proxy.String()).Msgf("Error looking up MeshServices associated with proxy")
		return nil, err
	}

	// --- OUTBOUND -------------------
	outboundLis := lds.ListenerBuilder().
		Name(lds.OutboundListenerName).
		ProxyIdentity(proxy.Identity).
		Address(constants.WildcardIPAddr, constants.EnvoyOutboundListenerPort).
		TrafficDirection(xds_core.TrafficDirection_OUTBOUND).
		PermissiveMesh(meshConfig.Spec.Traffic.EnablePermissiveTrafficPolicyMode).
		OutboundMeshTrafficPolicy(g.catalog.GetOutboundMeshTrafficPolicy(proxy.Identity)).
		ActiveHealthCheck(meshConfig.Spec.FeatureFlags.EnableEnvoyActiveHealthChecks)

	if meshConfig.Spec.Traffic.EnableEgress {
		outboundLis.PermissiveEgress(true)
	} else {
		egressPolicy, err := g.catalog.GetEgressTrafficPolicy(proxy.Identity)
		if err != nil {
			return nil, fmt.Errorf("error building LDS response: %w", err)
		}
		outboundLis.EgressTrafficPolicy(egressPolicy)
	}
	if meshConfig.Spec.Observability.Tracing.Enable {
		outboundLis.TracingEndpoint(utils.GetTracingEndpoint(meshConfig))
	}
	if meshConfig.Spec.FeatureFlags.EnableWASMStats {
		outboundLis.WASMStatsHeaders(statsHeaders)
	}

	outboundListener, err := outboundLis.Build()
	if err != nil {
		return nil, fmt.Errorf("error building outbound listener for proxy %s: %w", proxy, err)
	}
	if outboundListener == nil {
		// This check is important to prevent attempting to configure a listener without a filter chain which
		// otherwise results in an error.
		log.Debug().Str("proxy", proxy.String()).Msg("Not programming nil outbound listener")
	} else {
		ldsResources = append(ldsResources, outboundListener)
	}

	// --- INBOUND -------------------
	inboundLis := lds.ListenerBuilder().
		Name(lds.InboundListenerName).
		ProxyIdentity(proxy.Identity).
		TrustDomain(g.certManager.GetTrustDomain()).
		Address(constants.WildcardIPAddr, constants.EnvoyInboundListenerPort).
		TrafficDirection(xds_core.TrafficDirection_INBOUND).
		DefaultInboundListenerFilters().
		PermissiveMesh(meshConfig.Spec.Traffic.EnablePermissiveTrafficPolicyMode).
		InboundMeshTrafficPolicy(g.catalog.GetInboundMeshTrafficPolicy(proxy.Identity, svcList)).
		IngressTrafficPolicies(g.catalog.GetIngressTrafficPolicies(svcList)).
		ActiveHealthCheck(meshConfig.Spec.FeatureFlags.EnableEnvoyActiveHealthChecks).
		SidecarSpec(meshConfig.Spec.Sidecar)

	trafficTargets, err := g.catalog.ListInboundTrafficTargetsWithRoutes(proxy.Identity)
	if err != nil {
		return nil, fmt.Errorf("error building inbound listener: %w", err)
	}
	inboundLis.TrafficTargets(trafficTargets)

	if meshConfig.Spec.Observability.Tracing.Enable {
		inboundLis.TracingEndpoint(utils.GetTracingEndpoint(meshConfig))
	}
	if extAuthzConfig := utils.ExternalAuthConfigFromMeshConfig(meshConfig); extAuthzConfig.Enable {
		inboundLis.ExtAuthzConfig(&extAuthzConfig)
	}
	if meshConfig.Spec.FeatureFlags.EnableWASMStats {
		inboundLis.WASMStatsHeaders(statsHeaders)
	}

	inboundListener, err := inboundLis.Build()
	if err != nil {
		return nil, fmt.Errorf("error building inbound listener for proxy %s: %w", proxy, err)
	}
	if inboundListener != nil {
		ldsResources = append(ldsResources, inboundListener)
	}

	if enabled, err := g.catalog.IsMetricsEnabled(proxy); err != nil {
		log.Warn().Str("proxy", proxy.String()).Msgf("Could not find pod for connecting proxy, no metadata was recorded")
	} else if enabled {
		// Build Prometheus listener config
		if prometheusListener, err := lds.BuildPrometheusListener(); err != nil {
			log.Error().Err(err).Str("proxy", proxy.String()).Msgf("Error building Prometheus listener")
		} else {
			ldsResources = append(ldsResources, prometheusListener)
		}
	}

	return ldsResources, nil
}
