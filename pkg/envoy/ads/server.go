package ads

import (
	"context"
	"fmt"

	xds_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/k8s"
	"github.com/openservicemesh/osm/pkg/logger"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/workerpool"
)

const (
	// ServerType is the type identifier for the ADS server
	ServerType = "ADS"

	// workerPoolSize is the default number of workerpool workers (0 is GOMAXPROCS)
	workerPoolSize = 0

	// xdsServerCertificateCommonName is the common name of the certificate for the ADS server
	xdsServerCertificateCommonName = "ads"
)

// NewADSServer creates a new Aggregated Discovery Service server
func NewADSServer(meshCatalog catalog.MeshCataloger, proxyRegistry *registry.ProxyRegistry, enableDebug bool, osmNamespace string,
	certManager *certificate.Manager, kubecontroller k8s.Controller, msgBroker *messaging.Broker) *Server {
	server := Server{
		controlPlane  *osm.ControlPlane[map[string][]types.Resource]
		catalog:       meshCatalog,
		proxyRegistry: proxyRegistry,
		osmNamespace:  osmNamespace,
		certManager:   certManager,
		snapshotCache: cachev3.NewSnapshotCache(false, cachev3.IDHash{}, &scLogger{
			log: logger.New("envoy/snapshot-cache"),
		}),
		workqueues:     workerpool.NewWorkerPool(workerPoolSize),
		kubecontroller: kubecontroller,
		configVersion:  make(map[string]uint64),
		msgBroker:      msgBroker,
	}

	return &server
}

// Start starts the ADS server
func (s *Server) Start(ctx context.Context, cancel context.CancelFunc, port int, adsCert *certificate.Certificate) error {
	grpcServer, lis, err := NewGrpc(ServerType, port, xdsServerCertificateCommonName, s.certManager)
	if err != nil {
		return fmt.Errorf("error starting ADS server: %w", err)
	}

	xds_discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer.GetServer(), serverv3.NewServer(ctx, s.snapshotCache, s))

	err = grpcServer.GrpcServe(ctx, cancel, lis, nil)
	if err != nil {
		return fmt.Errorf("error starting ADS server: %w", err)
	}

	s.ready = true

	return nil
}
