// Package identity implements types and utility routines related to the identity of a workload, as used within OSM.
package identity

import (
	"fmt"
	"strings"

	"github.com/openservicemesh/osm/pkg/certificate"
)

const (
	// saSeparator used upon marshalling/unmarshalling MeshService to a string or viceversa
	saSeparator = "/"
)

// ServiceIdentity is the type used to represent the identity for a service
// For Kubernetes services this string will be in the format: <ServiceAccount>.<Namespace>.cluster.local
// In an ideal world we would set the ServiceIdentity to <ServiceAccount>.<Namespace>.cluster.<ClusterID>
type ServiceIdentity string

// String returns the ServiceIdentity as a string
func (si ServiceIdentity) String() string {
	return string(si)
}

// GetSDSCSecretName returns a string key used as the name of Certificate in all SDS structs.
// TODO(draychev): Remove this once the transition to ServiceIdentity is complete [https://github.com/openservicemesh/osm/issues/3182]
func (si ServiceIdentity) GetSDSCSecretName() string {
	// TODO(draychev): The cert names can be redone to move away from using "namespace/name" format [https://github.com/openservicemesh/osm/issues/2218]
	// Currently this will be: "service-cert:default/bookbuyer"
	return si.ToK8sServiceAccount().String()
}

// GetCertificateCommonName returns a certificate CommonName compliant with RFC-1123 (https://tools.ietf.org/html/rfc1123) DNS name.
// TODO(draychev): Remove this once the transition to ServiceIdentity is complete [https://github.com/openservicemesh/osm/issues/3182]
func (si ServiceIdentity) GetCertificateCommonName() certificate.CommonName {
	return certificate.CommonName(si)
}

func (si ServiceIdentity) SubjectAltNames(domains ...string) []ServiceIdentity {
	sa := si.ToK8sServiceAccount()
	// TODO(steeling) don't hardcode this
	return []ServiceIdentity{
		ServiceIdentity(fmt.Sprintf("%s.%s.%s", sa.Name, sa.Namespace, "cluster.local")),
		ServiceIdentity(fmt.Sprintf("%s.%s.%s", sa.Name, sa.Namespace, "cluster.remote-clusterx")),
		ServiceIdentity(fmt.Sprintf("%s.%s.%s", sa.Name, sa.Namespace, "cluster.global")),
	}
}

// ToK8sServiceAccount converts a ServiceIdentity to a K8sServiceAccount to help with transition from K8sServiceAccount to ServiceIdentity
func (si ServiceIdentity) ToK8sServiceAccount() K8sServiceAccount {
	// By convention as of release-v0.8 ServiceIdentity is in the format: <ServiceAccount>.<Namespace>.<cluster-domain>
	// We can split by "." and will have service account in the first position and namespace in the second.
	chunks := strings.Split(si.String(), ".")
	name := chunks[0]
	namespace := chunks[1]
	return K8sServiceAccount{
		Namespace: namespace,
		Name:      name,
	}
}

// K8sServiceAccount is a type for a namespaced service account
type K8sServiceAccount struct {
	Namespace string
	Name      string
}

// String returns the string representation of the service account object
func (sa K8sServiceAccount) String() string {
	return strings.Join([]string{sa.Namespace, sa.Name, sa.ClusterName}, saSeparator)
}

// IsEmpty returns true if the given service account object is empty
func (sa K8sServiceAccount) IsEmpty() bool {
	return (K8sServiceAccount{}) == sa
}

// ToServiceIdentity converts K8sServiceAccount to the newer ServiceIdentity
// TODO(draychev): ToServiceIdentity is used in many places to ease with transition from K8sServiceAccount to ServiceIdentity and should be removed (not everywhere) - [https://github.com/openservicemesh/osm/issues/2218]
func (sa K8sServiceAccount) ToServiceIdentity() ServiceIdentity {
	// TODO(steeling): look into this, maybe set this directly to the remote..
	return ServiceIdentity(fmt.Sprintf("%s.%s.%s", sa.Name, sa.Namespace, ClusterLocalTrustDomain))
}
