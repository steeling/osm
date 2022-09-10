package ads

import (
	"context"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/openservicemesh/osm/pkg/metricsstore"
)

// OnStreamOpen is called on stream open
func (s *Server) OnStreamOpen(ctx context.Context, streamID int64, typ string) error {
	log.Debug().Msgf("OnStreamOpen id: %d typ: %s", streamID, typ)
	return nil
}

// OnStreamClosed is called on stream closed
func (s *Server) OnStreamClosed(streamID int64) {
	log.Debug().Msgf("OnStreamClosed id: %d", streamID)
	s.proxyRegistry.UnregisterProxy(streamID)

	metricsstore.DefaultMetricsStore.ProxyConnectCount.Dec()
}

// OnStreamRequest is called when a request happens on an open connection
func (s *Server) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	log.Debug().Msgf("OnStreamRequest node: %s, type: %s, v: %s, nonce: %s, resNames: %s", req.Node.Id, req.TypeUrl, req.VersionInfo, req.ResponseNonce, req.ResourceNames)

	proxy := s.proxyRegistry.GetConnectedProxy(streamID)
	if proxy != nil {
		metricsstore.DefaultMetricsStore.ProxyXDSRequestCount.WithLabelValues(proxy.UUID.String(), proxy.Identity.String(), req.TypeUrl).Inc()
	}

	return nil
}

// OnStreamResponse is called when a response is being sent to a request
func (s *Server) OnStreamResponse(_ context.Context, streamID int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	log.Debug().Msgf("OnStreamResponse RESP: %d type: %s, v: %s, nonce: %s, NumResources: %d", streamID, resp.TypeUrl, resp.VersionInfo, resp.Nonce, len(resp.Resources))
}

// --- Fetch request types. Callback interfaces still requires these to be defined

// OnFetchRequest is called when a fetch request is received
func (s *Server) OnFetchRequest(_ context.Context, req *discovery.DiscoveryRequest) error {
	// Unimplemented
	return errUnsuportedXDSRequest
}

// OnFetchResponse is called when a fetch request is being responded to
func (s *Server) OnFetchResponse(req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	// Unimplemented
}

// --- Delta stream types below. Callback interfaces still requires these to be defined

// OnDeltaStreamOpen is called when a Delta stream is being opened
func (s *Server) OnDeltaStreamOpen(_ context.Context, id int64, typ string) error {
	// Unimplemented
	return errUnsuportedXDSRequest
}

// OnDeltaStreamClosed is called when a Delta stream is being closed
func (s *Server) OnDeltaStreamClosed(id int64) {
	// Unimplemented
}

// OnStreamDeltaRequest is called when a Delta request comes on an open Delta stream
func (s *Server) OnStreamDeltaRequest(a int64, req *discovery.DeltaDiscoveryRequest) error {
	// Unimplemented
	return errUnsuportedXDSRequest
}

// OnStreamDeltaResponse is called when a Delta request is getting responded to
func (s *Server) OnStreamDeltaResponse(a int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	// Unimplemented
}
