package fake

import (
	"github.com/openservicemesh/osm/pkg/endpoint"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/service"
	"github.com/openservicemesh/osm/pkg/tests"
)

// Provider interface combines endpoint.Provider and service.Provider
type Provider interface {
	endpoint.Provider
	service.Provider
}

// NewFakeProvider implements mesh.EndpointsProvider, which creates a test Kubernetes cluster/compute provider.
func NewFakeProvider() Provider {
	return &fakeClient{
		endpoints: map[string][]endpoint.Endpoint{
			tests.BookstoreV1Service.String():   {tests.Endpoint},
			tests.BookstoreV2Service.String():   {tests.Endpoint},
			tests.BookbuyerService.String():     {tests.Endpoint},
			tests.BookstoreApexService.String(): {tests.Endpoint},
		},
		services: map[identity.ServiceIdentity][]service.MeshService{
			tests.BookstoreServiceIdentity:   {tests.BookstoreV1Service, tests.BookstoreApexService},
			tests.BookstoreV2ServiceIdentity: {tests.BookstoreV2Service},
			tests.BookbuyerServiceIdentity:   {tests.BookbuyerService},
		},
		svcAccountEndpoints: map[identity.ServiceIdentity][]endpoint.Endpoint{
			tests.BookstoreServiceIdentity:   {tests.Endpoint, tests.Endpoint},
			tests.BookstoreV2ServiceIdentity: {tests.Endpoint},
			tests.BookbuyerServiceIdentity:   {tests.Endpoint},
		},
	}
}

type fakeClient struct {
	endpoints           map[string][]endpoint.Endpoint
	services            map[identity.ServiceIdentity][]service.MeshService
	svcAccountEndpoints map[identity.ServiceIdentity][]endpoint.Endpoint
}

// ListEndpointsForService retrieves the IP addresses comprising the given service.
func (f *fakeClient) ListEndpointsForService(svc service.MeshService) []endpoint.Endpoint {
	return f.endpoints[svc.String()]
}

// ListEndpointsForIdentity retrieves the IP addresses comprising the given service account.
// Note: ServiceIdentity must be in the format "name.namespace" [https://github.com/openservicemesh/osm/issues/3188]
func (f *fakeClient) ListEndpointsForIdentity(serviceIdentity identity.ServiceIdentity) []endpoint.Endpoint {
	return f.svcAccountEndpoints[serviceIdentity]
}

func (f *fakeClient) GetServicesForServiceIdentity(serviceIdentity identity.ServiceIdentity) []service.MeshService {
	return f.services[serviceIdentity]
}

func (f *fakeClient) ListServices() []service.MeshService {
	var services []service.MeshService

	for _, svcs := range f.services {
		services = append(services, svcs...)
	}
	return services
}

func (f *fakeClient) ListServiceIdentitiesForService(svc service.MeshService) []identity.ServiceIdentity {
	var serviceIdentities []identity.ServiceIdentity

	for svcID := range f.services {
		serviceIdentities = append(serviceIdentities, svcID)
	}
	return serviceIdentities
}

// GetID returns the unique identifier of the Provider.
func (f *fakeClient) GetID() string {
	return "Fake Kubernetes Client"
}

func (f *fakeClient) GetResolvableEndpointsForService(svc service.MeshService) []endpoint.Endpoint {
	return f.endpoints[svc.String()]
}

func (f *fakeClient) GetServicesForProxy(proxy *envoy.Proxy) ([]service.MeshService, error) {
	// It's the same here since there are no unique pods.
	return f.GetServicesForServiceIdentity(proxy.Identity), nil
}
