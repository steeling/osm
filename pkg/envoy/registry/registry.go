package registry

import (
	"github.com/openservicemesh/osm/pkg/envoy"
)

// New initializes a new empty *ProxyRegistry.
func New() *ProxyRegistry {
	return &ProxyRegistry{
		connectedProxies: make(map[string]*envoy.Proxy),
	}
}

// RegisterProxy registers a newly connected proxy.
func (pr *ProxyRegistry) RegisterProxy(proxy *envoy.Proxy) {
	// TODO(#4950) check register request sequence before proceeding
	uuid := proxy.UUID.String()
	if pr.GetConnectedProxy(uuid) != nil {
		log.Debug().Str("proxy", proxy.String()).Msgf("Proxy %s already registered", proxy.String())
		return
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.connectedProxies[uuid] = proxy
	log.Debug().Str("proxy", proxy.String()).Msg("Registered new proxy")
}

// GetConnectedProxy loads a connected proxy from the registry.
func (pr *ProxyRegistry) GetConnectedProxy(uuid string) *envoy.Proxy {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return pr.connectedProxies[uuid]
}

// UnregisterProxy unregisters the given proxy from the catalog.
func (pr *ProxyRegistry) UnregisterProxy(proxy *envoy.Proxy) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	delete(pr.connectedProxies, proxy.UUID.String())
	log.Debug().Msgf("Unregistered proxy %s", proxy.String())
}

// GetConnectedProxyCount counts the number of connected proxies
func (pr *ProxyRegistry) GetConnectedProxyCount() int {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	return len(pr.connectedProxies)
}

// ListConnectedProxies lists the Envoy proxies already connected and the time they first connected.
func (pr *ProxyRegistry) ListConnectedProxies() map[string]*envoy.Proxy {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	proxies := make(map[string]*envoy.Proxy)
	for uuid, p := range pr.connectedProxies {
		proxies[uuid] = p
	}
	return proxies
}
