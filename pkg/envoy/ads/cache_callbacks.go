package ads

import (
	"context"
	"fmt"
	"sync"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"go.uber.org/atomic"

	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/metricsstore"
	"github.com/openservicemesh/osm/pkg/utils"
)

var minUpdateResyncPeriod = time.Minute

// OnStreamOpen is called on stream open
func (s *Server) OnStreamOpen(ctx context.Context, streamID int64, typ string) error {
	log.Debug().Msgf("OnStreamOpen id: %d typ: %s", streamID, typ)
	// When a new Envoy proxy connects, ValidateClient would ensure that it has a valid certificate,
	// and the Subject CN is in the allowedCommonNames set.
	certCommonName, certSerialNumber, err := utils.ValidateClient(ctx)
	if err != nil {
		return fmt.Errorf("Could not start Aggregated Discovery Service gRPC stream for newly connected Envoy proxy: %w", err)
	}

	// If maxDataPlaneConnections is enabled i.e. not 0, then check that the number of Envoy connections is less than maxDataPlaneConnections
	if s.catalog.GetMeshConfig().Spec.Sidecar.MaxDataPlaneConnections > 0 && s.proxyRegistry.GetConnectedProxyCount() >= s.catalog.GetMeshConfig().Spec.Sidecar.MaxDataPlaneConnections {
		metricsstore.DefaultMetricsStore.ProxyMaxConnectionsRejected.Inc()
		return errTooManyConnections
	}

	log.Trace().Msgf("Envoy with certificate SerialNumber=%s connected", certSerialNumber)
	metricsstore.DefaultMetricsStore.ProxyConnectCount.Inc()

	kind, uuid, si, err := getCertificateCommonNameMeta(certCommonName)
	if err != nil {
		return fmt.Errorf("error parsing certificate common name %s: %w", certCommonName, err)
	}

	proxy := envoy.NewProxy(kind, uuid, si, utils.GetIPFromContext(ctx), streamID)

	if err := s.catalog.VerifyProxy(proxy); err != nil {
		return err
	}

	s.proxyRegistry.RegisterProxy(proxy)
	go s.watchProxyUpdates(ctx, proxy)
	return nil
}

// watchProxyUpdates watches and schedules proxy updates, either due to broadcasts from the message broker, certificate
// rotations, or after `minUpdateResyncPeriod` from the last update. It works via the following algorithm:
// 1. Watches for broadcast, cert rotation, and timer based updates. When an event is seen, we check if an update is
// already in progress. If there is an update in progress, we mark a `needsUpdate` bool to true, in case something has
// changed mid update, and we need to capture it with a new sync.
// When the prior update completes, we stop and reset the timer to `minUpdateResyncPeriod`, and if `needsUpdate` is true
// we immediately schedule a new update.
func (s *Server) watchProxyUpdates(ctx context.Context, proxy *envoy.Proxy) {
	// Register for proxy config updates broadcasted by the message broker
	proxyUpdatePubSub := s.msgBroker.GetProxyUpdatePubSub()
	proxyUpdateChan := proxyUpdatePubSub.Sub(messaging.ProxyUpdateTopic, messaging.GetPubSubTopicForProxyUUID(proxy.UUID.String()))
	defer s.msgBroker.Unsub(proxyUpdatePubSub, proxyUpdateChan)

	certRotations, unsubRotations := s.certManager.SubscribeRotations(proxy.Identity.String())
	defer unsubRotations()

	var mu sync.Mutex
	// Needs to be of size one since we add to it on the same routine we listen on.
	updateChan := make(chan any, 1)
	timer := time.NewTimer(minUpdateResyncPeriod)
	var needsUpdate atomic.Bool
	// want:
	// 1. A timer that is reset when the call finishes
	// 2. An additional call to add another send if the
	updateDone := func() {
		shouldUpdate := needsUpdate.Load()
		// Update to false while holding this lock, to not erase a reset to true.
		// It could get incorrectly over written to true still, but this is better than getting incorrectly
		// overwritten to false.
		needsUpdate.Store(false)
		if !timer.Stop() {
			<-timer.C
		}
		timer.Reset(minUpdateResyncPeriod)
		mu.Unlock()
		if shouldUpdate {
			updateChan <- struct{}{}
		}
	}

	// schedule a single update to start. This is required to support proxies reconnecting.
	updateChan <- struct{}{}

	for {
		// NOTE(#4847): since we're listening on pubsub channels, nothing should block in this routine. Blocking in this
		// routine can cause delays to all `watchProxyUpdates` routines, delaying updates to all proxies.
		select {
		case <-timer.C:
			log.Debug().Str("proxy", proxy.String()).Msg("haven't updated the proxy in over 1 minute, sending a new update.")
			updateChan <- struct{}{}
		case <-proxyUpdateChan:
			log.Debug().Str("proxy", proxy.String()).Msg("Broadcast update received")
			updateChan <- struct{}{}
		case <-certRotations:
			log.Debug().Str("proxy", proxy.String()).Msg("Certificate has been updated for proxy")
			updateChan <- struct{}{}
		case <-updateChan:
			if mu.TryLock() {
				s.scheduleUpdate(proxy, updateDone)
			} else {
				needsUpdate.Store(true)
				log.Debug().Str("proxy", proxy.String()).Msg("skipping update due to in process update")
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) scheduleUpdate(proxy *envoy.Proxy, done func()) {
	s.workqueues.AddJob(
		func() {
			t := time.Now()
			log.Debug().Msgf("Starting update for proxy %s", proxy.String())

			if err := s.update(proxy); err != nil {
				log.Error().Err(err).Str("proxy", proxy.String()).Msg("Error generating resources for proxy")
			}
			log.Debug().Msgf("Update for proxy %s took took %v", proxy.String(), time.Since(t))
			done()
		})
}

func (s *Server) update(proxy *envoy.Proxy) error {
	resources, err := s.GenerateResources(proxy)
	if err != nil {
		return err
	}
	if err := s.ServeResources(proxy, resources); err != nil {
		return err
	}
	log.Debug().Msgf("successfully updated resources for proxy %s", proxy.String())
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
