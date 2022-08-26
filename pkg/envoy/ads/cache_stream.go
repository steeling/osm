package ads

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/google/uuid"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/identity"
)

// RecordFullSnapshot stores a group of resources as a new Snapshot with a new version in the cache.
// It also runs a consistency check on the snapshot (will warn if there are missing resources referenced in
// the snapshot)
func (s *Server) RecordFullSnapshot(proxy *envoy.Proxy, snapshotResources map[string][]types.Resource) error {
	snapshot, err := cache.NewSnapshot(
		fmt.Sprintf("%d", s.configVersion[proxy.UUID.String()]),
		snapshotResources,
	)
	if err != nil {
		return err
	}

	if err := snapshot.Consistent(); err != nil {
		log.Warn().Err(err).Str("proxy", proxy.String()).Msgf("Snapshot for proxy not consistent")
	}

	s.configVerMutex.Lock()
	defer s.configVerMutex.Unlock()
	s.configVersion[proxy.UUID.String()]++

	return s.snapshotCache.SetSnapshot(context.TODO(), proxy.UUID.String(), snapshot)
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

// recordPodMetadata records pod metadata and verifies the certificate issued for this pod
// is for the same service account as seen on the pod's service account
func (s *Server) recordPodMetadata(p *envoy.Proxy) error {
	pod, err := s.kubecontroller.GetPodForProxy(p)
	if err != nil {
		log.Warn().Str("proxy", p.String()).Msg("Could not find pod for connecting proxy. No metadata was recorded.")
		return nil
	}

	workloadKind := ""
	workloadName := ""
	for _, ref := range pod.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			workloadKind = ref.Kind
			workloadName = ref.Name
			break
		}
	}

	p.PodMetadata = &envoy.PodMetadata{
		UID:       string(pod.UID),
		Name:      pod.Name,
		Namespace: pod.Namespace,
		ServiceAccount: identity.K8sServiceAccount{
			Namespace: pod.Namespace,
			Name:      pod.Spec.ServiceAccountName,
		},
		WorkloadKind: workloadKind,
		WorkloadName: workloadName,
	}

	// Verify Service account matches (cert to pod Service Account)
	if p.Identity.ToK8sServiceAccount() != p.PodMetadata.ServiceAccount {
		log.Error().Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMismatchedServiceAccount)).Str("proxy", p.String()).
			Msgf("Service Account referenced in NodeID (%s) does not match Service Account in Certificate (%s). This proxy is not allowed to join the mesh.", p.PodMetadata.ServiceAccount, p.Identity.ToK8sServiceAccount())
		return errServiceAccountMismatch
	}

	return nil
}

func (s *Server) GenerateResources(proxy *envoy.Proxy) (map[string][]types.Resource, error) {
	thereWereErrors := false
	cacheResourceMap := map[string][]types.Resource{}

	// Order is important: CDS, EDS, LDS, RDS
	// See: https://github.com/envoyproxy/go-control-plane/issues/59
	for _, typeURI := range envoy.XDSResponseOrder {
		// resources below ..

		// Generate the resources for this request
		// Tracks the success of this TypeURI response operation; accounts also for receipt on envoy server side
		startedAt := time.Now()
		log.Trace().Str("proxy", proxy.String()).Msgf("Getting resources for type %s", typeURI.Short())

		handler, ok := s.xdsHandlers[typeURI]
		if !ok {
			return nil, errUnknownTypeURL
		}

		if s.catalog.GetMeshConfig().Spec.Observability.EnableDebugServer {
			s.trackXDSLog(proxy.GetName(), typeURI)
		}

		// Invoke XDS handler
		resources, err := handler(s.catalog, proxy, s.certManager, s.proxyRegistry)
		xdsPathTimeTrack(startedAt, typeURI, proxy, err == nil)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrGeneratingReqResource)).Str("proxy", proxy.String()).
				Msgf("Error generating response for typeURI: %s", typeURI.Short())
			thereWereErrors = true
			continue
		}
		// resources above ^^

		// Keep a reference to later set the full snapshot in the cache
		cacheResourceMap[typeURI.String()] = resources
	}

	// Store the aggregated resources as a full snapshot
	if err := s.RecordFullSnapshot(proxy, cacheResourceMap); err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrRecordingSnapshot)).Str("proxy", proxy.String()).
			Msgf("Error recording snapshot for proxy: %v", err)
		thereWereErrors = true
	}

	xdsPathTimeTrack(time.Now(), envoy.TypeADS, proxy, !thereWereErrors)
}
