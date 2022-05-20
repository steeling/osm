// Package identity implements types and utility routines related to the identity of a workload, as used within OSM.
package identity

import (
	"fmt"
	"strings"
)

const (
	// namespaceNameSeparator used for marshalling/unmarshalling MeshService to a string or vice versa
	namespaceNameSeparator = "/"
)

// ServiceIdentity is the type used to represent the identity for a service
// For Kubernetes services this string will be in the format: <ServiceAccount>.<Namespace>.cluster.local
type ServiceIdentity struct {
	Name        string
	Namespace   string
	TrustDomain string
}

func ServiceIdentityFromString(si string) ServiceIdentity {
	name, remainder, _ := strings.Cut(si, ".")
	namespace, trustDomain, _ := strings.Cut(remainder, ".")
	return ServiceIdentity{
		Name:        name,
		Namespace:   namespace,
		TrustDomain: trustDomain,
	}
}

// WildcardServiceIdentity is a wildcard to match all service identities
var WildcardServiceIdentity = ServiceIdentity{Name: "*"}

// String returns the ServiceIdentity as a string
func (si ServiceIdentity) String() string {
	return strings.Join([]string{si.Name, si.Namespace, si.TrustDomain}, namespaceNameSeparator)
}

// IsWildcard determines if the ServiceIdentity is a wildcard
func (si ServiceIdentity) IsWildcard() bool {
	return si == WildcardServiceIdentity
}

// ToK8sServiceAccount converts a ServiceIdentity to a K8sServiceAccount to help with transition from K8sServiceAccount to ServiceIdentity
func (si ServiceIdentity) ToK8sServiceAccount() K8sServiceAccount {
	return K8sServiceAccount{
		Namespace: si.Namespace,
		Name:      si.Name,
	}
}

// K8sServiceAccount is a type for a namespaced service account
type K8sServiceAccount struct {
	Namespace string
	Name      string
}

// String returns the string representation of the service account object
func (sa K8sServiceAccount) String() string {
	return fmt.Sprintf("%s%s%s", sa.Namespace, namespaceNameSeparator, sa.Name)
}

// ToServiceIdentity converts K8sServiceAccount to the newer ServiceIdentity
// TODO(draychev): ToServiceIdentity is used in many places to ease with transition from K8sServiceAccount to ServiceIdentity and should be removed (not everywhere) - [https://github.com/openservicemesh/osm/issues/2218]
func (sa K8sServiceAccount) ToServiceIdentity(trustDomain string) ServiceIdentity {
	return ServiceIdentity{
		Name:        sa.Name,
		Namespace:   sa.Namespace,
		TrustDomain: trustDomain,
	}
}
