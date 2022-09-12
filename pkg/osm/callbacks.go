package osm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/metricsstore"
	"github.com/openservicemesh/osm/pkg/utils"
)

// OnStreamOpen is called on stream open
func (cp *ControlPlane[T]) ProxyConnected(ctx context.Context, connectionID int64) error {
	// When a new Envoy proxy connects, ValidateClient would ensure that it has a valid certificate,
	// and the Subject CN is in the allowedCommonNames set.
	certCommonName, certSerialNumber, err := utils.ValidateClient(ctx)
	if err != nil {
		return fmt.Errorf("Could not start cannot connect proxy for stream id %d: %w", connectionID, err)
	}

	// If maxDataPlaneConnections is enabled i.e. not 0, then check that the number of Envoy connections is less than maxDataPlaneConnections
	if cp.catalog.GetMeshConfig().Spec.Sidecar.MaxDataPlaneConnections > 0 && cp.proxyRegistry.GetConnectedProxyCount() >= cp.catalog.GetMeshConfig().Spec.Sidecar.MaxDataPlaneConnections {
		metricsstore.DefaultMetricsStore.ProxyMaxConnectionsRejected.Inc()
		return errTooManyConnections
	}

	log.Trace().Msgf("Envoy with certificate SerialNumber=%s connected", certSerialNumber)
	metricsstore.DefaultMetricsStore.ProxyConnectCount.Inc()

	kind, uuid, si, err := getCertificateCommonNameMeta(certCommonName)
	if err != nil {
		return fmt.Errorf("error parsing certificate common name %s: %w", certCommonName, err)
	}

	proxy := envoy.NewProxy(kind, uuid, si, utils.GetIPFromContext(ctx), connectionID)

	if err := cp.catalog.VerifyProxy(proxy); err != nil {
		return err
	}

	cp.proxyRegistry.RegisterProxy(proxy)
	go func() {
		// Register for proxy config updates broadcasted by the message broker
		proxyUpdatePubSub := cp.msgBroker.GetProxyUpdatePubSub()
		proxyUpdateChan := proxyUpdatePubSub.Sub(messaging.ProxyUpdateTopic, messaging.GetPubSubTopicForProxyUUID(proxy.UUID.String()))
		defer cp.msgBroker.Unsub(proxyUpdatePubSub, proxyUpdateChan)

		certRotations, unsubRotations := cp.certManager.SubscribeRotations(proxy.Identity.String())
		defer unsubRotations()

		// schedule one update for this proxy initially.

		var mu sync.Mutex
		mu.Lock()
		cp.scheduleUpdate(ctx, proxy, mu.Unlock)
		// Needs to be of size one since we add to it on the same routine we listen on.
		updateChan := make(chan any, 1)
		timer := time.NewTimer(time.Minute)
		var needsUpdate atomic.Bool
		// want:
		// 1. A timer that is reset when the call finishes
		// 2. An additional call to add another send if the
		for {
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
					cp.scheduleUpdate(ctx, proxy, func() {
						shouldUpdate := needsUpdate.Load()
						// Update to false while holding this lock, to not erase a reset to true.
						// It could get incorrectly over written to true still, but this is better than getting incorrectly
						// overwritten to false.
						needsUpdate.Store(false)
						if !timer.Stop() {
							<-timer.C
						}
						timer.Reset(time.Minute)
						mu.Unlock()
						if shouldUpdate {
							updateChan <- struct{}{}
						}
					})
				} else {
					needsUpdate.Store(true)
					log.Debug().Str("proxy", proxy.String()).Msg("skipping update due to in process update")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (cp *ControlPlane[T]) scheduleUpdate(ctx context.Context, proxy *envoy.Proxy, done func()) {
	cp.workqueues.AddJob(
		func() {
			t := time.Now()
			log.Debug().Msgf("Starting update for proxy %s", proxy.String())

			if err := cp.update(ctx, proxy); err != nil {
				log.Error().Err(err).Str("proxy", proxy.String()).Msg("Error generating resources for proxy")
			}
			log.Debug().Msgf("Update for proxy %s took took %v", proxy.String(), time.Since(t))
			done()
		})
}

func (cp *ControlPlane[T]) update(ctx context.Context, proxy *envoy.Proxy) error {
	resources, err := cp.configGenerator.GenerateConfig(ctx, proxy)
	if err != nil {
		return err
	}
	if err := cp.configServer.ServeConfig(ctx, proxy, resources); err != nil {
		return err
	}
	log.Debug().Msgf("successfully updated resources for proxy %s", proxy.String())
	return nil
}

// OnStreamClosed is called on stream closed
func (cp *ControlPlane[T]) ProxyDisconnected(connectionID int64) {
	log.Debug().Msgf("OnStreamClosed id: %d", connectionID)
	cp.proxyRegistry.UnregisterProxy(connectionID)

	metricsstore.DefaultMetricsStore.ProxyConnectCount.Dec()
}

func getCertificateCommonNameMeta(cn certificate.CommonName) (envoy.ProxyKind, uuid.UUID, identity.ServiceIdentity, error) {
	// XDS cert CN is of the form <proxy-UUID>.<kind>.<proxy-identity>.<trust-domain>
	chunks := strings.SplitN(cn.String(), constants.DomainDelimiter, 5)
	if len(chunks) < 4 {
		return "", uuid.UUID{}, "", errInvalidCertificateCN
	}
	proxyUUID, err := uuid.Parse(chunks[0])
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrParsingXDSCertCN)).
			Msgf("Error parsing %s into uuid.UUID", chunks[0])
		return "", uuid.UUID{}, "", err
	}

	switch {
	case chunks[1] == "":
		return "", uuid.UUID{}, "", errInvalidCertificateCN
	case chunks[2] == "":
		return "", uuid.UUID{}, "", errInvalidCertificateCN
	case chunks[3] == "":
		return "", uuid.UUID{}, "", errInvalidCertificateCN
	}

	return envoy.ProxyKind(chunks[1]), proxyUUID, identity.New(chunks[2], chunks[3]), nil
}
