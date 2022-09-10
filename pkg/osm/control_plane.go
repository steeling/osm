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

type ProxyConfigServer[T any] interface {
	ServeConfig(context.Context, *envoy.Proxy, T) error
	Healthy(ctx context.Context) error
}

type ProxyConfigGenerator[T any] interface {
	GenerateConfig(context.Context, *envoy.Proxy) (T, error)
	Healthy(ctx context.Context) error
}

type ControlPlane[T any] struct {
	ConfigServer    ProxyConfigServer[T]
	ConfigGenerator ProxyConfigGenerator[T]

	catalog       catalog.MeshCataloger
	proxyRegistry *registry.ProxyRegistry
	osmNamespace  string
	certManager   *certificate.Manager
	workqueues    *workerpool.WorkerPool

	msgBroker *messaging.Broker
}
