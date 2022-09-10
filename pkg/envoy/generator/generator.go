package generator

import (
	"context"
	"sync"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/logger"
)

var (
	log = logger.New("envoy/generator")
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
			g.trackXDSLog(proxy.UUID.String(), typeURI)
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
