package osm

import (
	"context"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/workerpool"
)

const (
	workerPoolSize = 0
)

type ProxyConfigServer[T any] interface {
	ServeConfig(context.Context, *envoy.Proxy, T) error
}

type ProxyConfigGenerator[T any] interface {
	GenerateConfig(context.Context, *envoy.Proxy) (T, error)
}

type ControlPlane[T any] struct {
	configServer    ProxyConfigServer[T]
	configGenerator ProxyConfigGenerator[T]

	catalog       catalog.MeshCataloger
	proxyRegistry *registry.ProxyRegistry
	certManager   *certificate.Manager
	workqueues    *workerpool.WorkerPool
	msgBroker     *messaging.Broker
}

func NewControlPlane[T any](server ProxyConfigServer[T],
	generator ProxyConfigGenerator[T],
	catalog catalog.MeshCataloger,
	proxyRegistry *registry.ProxyRegistry,
	certManager *certificate.Manager,
	msgBroker *messaging.Broker,
) *ControlPlane[T] {
	return &ControlPlane[T]{
		configServer:    server,
		configGenerator: generator,
		catalog:         catalog,
		proxyRegistry:   proxyRegistry,
		certManager:     certManager,
		workqueues:      workerpool.NewWorkerPool(workerPoolSize),
		msgBroker:       msgBroker,
	}
}
