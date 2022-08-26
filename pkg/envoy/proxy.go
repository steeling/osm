package envoy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openservicemesh/osm/pkg/identity"
)

// Proxy is a representation of an Envoy proxy connected to the xDS server.
// This should at some point have a 1:1 match to an Endpoint (which is a member of a meshed service).
type Proxy struct {
	// UUID of the proxy
	uuid.UUID

	Identity identity.ServiceIdentity

	net.Addr

	// The time this Proxy connected to the OSM control plane
	connectedAt time.Time
	// Connection ID is used to distinguish a single proxy that reconnects from the old proxy.
	// The one with the larger ID is the newer proxy.
	connectionID int64

	// kind is the proxy's kind (ex. sidecar, gateway)
	kind ProxyKind

	// Records metadata around the Kubernetes Pod on which this Envoy Proxy is installed.
	// This could be nil if the Envoy is not operating in a Kubernetes cluster (VM for example)
	// NOTE: This field may be not be set at the time Proxy struct is initialized. This would
	// eventually be set when the metadata arrives via the xDS protocol.
	PodMetadata *PodMetadata
}

func (p *Proxy) String() string {
	return fmt.Sprintf("[ProxyUUID=%s], [Pod metadata=%s]", p.UUID, p.PodMetadataString())
}

// PodMetadata is a struct holding information on the Pod on which a given Envoy proxy is installed
// This struct is initialized *eventually*, when the metadata arrives via xDS.
type PodMetadata struct {
	UID            string
	Name           string
	Namespace      string
	IP             string
	ServiceAccount identity.K8sServiceAccount
	Cluster        string
	EnvoyNodeID    string
	WorkloadKind   string
	WorkloadName   string
}

// HasPodMetadata answers the question - has the Pod metadata been recorded for the given Envoy proxy
func (p *Proxy) HasPodMetadata() bool {
	return p.PodMetadata != nil
}

// StatsHeaders returns the headers required for SMI metrics
func (p *Proxy) StatsHeaders() map[string]string {
	unknown := "unknown"
	podName := unknown
	podNamespace := unknown
	podControllerKind := unknown
	podControllerName := unknown

	if p.PodMetadata != nil {
		if len(p.PodMetadata.Name) > 0 {
			podName = p.PodMetadata.Name
		}
		if len(p.PodMetadata.Namespace) > 0 {
			podNamespace = p.PodMetadata.Namespace
		}
		if len(p.PodMetadata.WorkloadKind) > 0 {
			podControllerKind = p.PodMetadata.WorkloadKind
		}
		if len(p.PodMetadata.WorkloadName) > 0 {
			podControllerName = p.PodMetadata.WorkloadName
		}
	}

	// Assume ReplicaSets are controlled by a Deployment unless their names
	// do not contain a hyphen. This aligns with the behavior of the
	// Prometheus config in the OSM Helm chart.
	if podControllerKind == "ReplicaSet" {
		if hyp := strings.LastIndex(podControllerName, "-"); hyp >= 0 {
			podControllerKind = "Deployment"
			podControllerName = podControllerName[:hyp]
		}
	}

	return map[string]string{
		"osm-stats-pod":       podName,
		"osm-stats-namespace": podNamespace,
		"osm-stats-kind":      podControllerKind,
		"osm-stats-name":      podControllerName,
	}
}

// PodMetadataString returns relevant pod metadata as a string
func (p *Proxy) PodMetadataString() string {
	if p.PodMetadata == nil {
		return ""
	}
	return fmt.Sprintf("UID=%s, Namespace=%s, Name=%s, ServiceAccount=%s", p.PodMetadata.UID, p.PodMetadata.Namespace, p.PodMetadata.Name, p.PodMetadata.ServiceAccount.Name)
}

// GetName returns a unique name for this proxy based on the identity and uuid.
func (p *Proxy) GetName() string {
	return fmt.Sprintf("%s:%s", p.Identity.String(), p.UUID.String())
}

// GetConnectedAt returns the timestamp of when the given proxy connected to the control plane.
func (p *Proxy) GetConnectedAt() time.Time {
	return p.connectedAt
}

// GetConnectionID returns the connection ID of the proxy.
// Connection ID is used to distinguish a single proxy that reconnects from the old proxy.
// The one with the larger ID is the newer proxy.
// NOTE: it is not used properly in the old, StreamAggregatedResources, and only works properly for the SnapshotCache.
func (p *Proxy) GetConnectionID() int64 {
	return p.connectionID
}

// GetIP returns the IP address of the Envoy proxy connected to xDS.
func (p *Proxy) GetIP() net.Addr {
	return p.Addr
}

// Kind return the proxy's kind
func (p *Proxy) Kind() ProxyKind {
	return p.kind
}

// NewProxy creates a new instance of an Envoy proxy connected to the xDS servers.
func NewProxy(kind ProxyKind, uuid uuid.UUID, svcIdentity identity.ServiceIdentity, ip net.Addr, connectionID int64) *Proxy {
	return &Proxy{
		// Identity is of the form <name>.<namespace>.cluster.local
		Identity: svcIdentity,
		UUID:     uuid,

		Addr: ip,

		connectedAt:  time.Now(),
		connectionID: connectionID,

		kind: kind,
	}
}

// NewXDSCertCNPrefix returns a newly generated CommonName for a certificate of the form: <ProxyUUID>.<kind>.<identity>
// where identity itself is of the form <name>.<namespace>
func NewXDSCertCNPrefix(proxyUUID uuid.UUID, kind ProxyKind, si identity.ServiceIdentity) string {
	return fmt.Sprintf("%s.%s.%s", proxyUUID.String(), kind, si)
}
