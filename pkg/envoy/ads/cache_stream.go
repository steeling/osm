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

// GenerateResources generates and returns the resources for the given proxy.
func (s *Server) GenerateResources(proxy *envoy.Proxy) (map[string][]types.Resource, error) {
	cacheResourceMap := map[string][]types.Resource{}
	for _, typeURI := range envoy.XDSResponseOrder {
		log.Trace().Str("proxy", proxy.String()).Msgf("Getting resources for type %s", typeURI.Short())

		handler, ok := s.xdsHandlers[typeURI]
		if !ok {
			return nil, errUnknownTypeURL
		}

		if s.catalog.GetMeshConfig().Spec.Observability.EnableDebugServer {
			s.trackXDSLog(proxy.GetName(), typeURI)
		}

		startedAt := time.Now()
		resources, err := handler(s.catalog, proxy, s.certManager, s.proxyRegistry)
		xdsPathTimeTrack(startedAt, typeURI, proxy, err == nil)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrGeneratingReqResource)).Str("proxy", proxy.String()).
				Msgf("Error generating response for typeURI: %s", typeURI.Short())
			xdsPathTimeTrack(time.Now(), envoy.TypeADS, proxy, false)
			return nil, err
		}

		cacheResourceMap[typeURI.String()] = resources
	}

	xdsPathTimeTrack(time.Now(), envoy.TypeADS, proxy, true)
	return cacheResourceMap, nil
}

// ServeResources stores a group of resources as a new Snapshot with a new version in the cache.
// It also runs a consistency check on the snapshot (will warn if there are missing resources referenced in
// the snapshot)
func (s *Server) ServeResources(proxy *envoy.Proxy, snapshotResources map[string][]types.Resource) error {
	uuid := proxy.UUID.String()

	s.configVerMutex.Lock()
	s.configVersion[uuid]++
	configVersion := s.configVersion[uuid]
	s.configVerMutex.Unlock()

	snapshot, err := cache.NewSnapshot(fmt.Sprintf("%d", configVersion), snapshotResources)
	if err != nil {
		return err
	}

	if err := snapshot.Consistent(); err != nil {
		return err
	}

	return s.snapshotCache.SetSnapshot(context.TODO(), uuid, snapshot)
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
