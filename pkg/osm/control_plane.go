package osm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/messaging"
	"github.com/openservicemesh/osm/pkg/metricsstore"
	"github.com/openservicemesh/osm/pkg/utils"
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
	Server          ProxyConfigServer[T]
	ConfigGenerator ProxyConfigGenerator[T]

	catalog       catalog.MeshCataloger
	proxyRegistry *registry.ProxyRegistry
	osmNamespace  string
	certManager   *certificate.Manager
	workqueues    *workerpool.WorkerPool

	msgBroker *messaging.Broker
}

func (cp *ControlPlane[T]) OnProxyConnect(ctx context.Context, streamID int64) error {
	log.Debug().Msgf("OnStreamOpen id: %d typ: %s", streamID)
	// When a new Envoy proxy connects, ValidateClient would ensure that it has a valid certificate,
	// and the Subject CN is in the allowedCommonNames set.
	certCommonName, certSerialNumber, err := utils.ValidateClient(ctx)
	if err != nil {
		return fmt.Errorf("Could not start Aggregated Discovery Service gRPC stream for newly connected Envoy proxy: %w", err)
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

	proxy := envoy.NewProxy(kind, uuid, si, utils.GetIPFromContext(ctx), streamID)

	cp.proxyRegistry.RegisterProxy(proxy)
	go func() {
		// Register for proxy config updates broadcasted by the message broker
		proxyUpdatePubSub := cp.msgBroker.GetProxyUpdatePubSub()
		proxyUpdateChan := proxyUpdatePubSub.Sub(messaging.ProxyUpdateTopic, messaging.GetPubSubTopicForProxyUUID(proxy.UUID.String()))
		defer cp.msgBroker.Unsub(proxyUpdatePubSub, proxyUpdateChan)

		certRotations, unsubRotations := cp.certManager.SubscribeRotations(proxy.Identity.String())
		defer unsubRotations()

		// schedule one update for this proxy initially.
		cp.scheduleUpdate(ctx, proxy)
		for {
			select {
			case <-proxyUpdateChan:
				log.Debug().Str("proxy", proxy.String()).Msg("Broadcast update received")
				cp.scheduleUpdate(ctx, proxy)
			case <-certRotations:
				log.Debug().Str("proxy", proxy.String()).Msg("Certificate has been updated for proxy")
				cp.scheduleUpdate(ctx, proxy)
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (cp *ControlPlane[T]) OnProxyDisconnect(streamID int64) {
	log.Info().Msgf("Proxy Disconnect id: %d", streamID)
	cp.proxyRegistry.UnregisterProxy(streamID)

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

func (cp *ControlPlane[T]) scheduleUpdate(ctx context.Context, proxy *envoy.Proxy) {
	var wg sync.WaitGroup
	wg.Add(1)
	cp.workqueues.AddJob(
		func() {
			t := time.Now()
			log.Debug().Msgf("Starting update for proxy %s", proxy.String())

			if err := cp.update(ctx, proxy); err != nil {
				log.Error().Err(err).Str("proxy", proxy.String()).Msg("Error generating resources for proxy")
			}
			log.Debug().Msgf("Update for proxy %s took took %v", proxy.String(), time.Since(t))
			wg.Done()
		})
	wg.Wait()
}

func (cp *ControlPlane[T]) update(ctx context.Context, proxy *envoy.Proxy) error {
	config, err := cp.ConfigGenerator.GenerateConfig(ctx, proxy)
	if err != nil {
		return err
	}
	if err := cp.Server.ServeConfig(ctx, proxy, config); err != nil {
		return err
	}
	log.Debug().Msgf("successfully updated resources for proxy %s", proxy.String())
	return nil
}
