// Package service models an instance of a service managed by OSM controller and utility routines associated with it.
package service

import "fmt"

const (
	// namespaceNameSeparator used upon marshalling/unmarshalling MeshService to a string
	// or viceversa
	namespaceNameSeparator = "/"
)

// MeshService is the struct defining a service (Kubernetes or otherwise) within a service mesh.
type MeshService struct {
	// If the service resides on a Kubernetes service, this would be the Kubernetes namespace.
	Namespace string

	// The name of the service
	Name string

	// The name of the cluster, ie: cluster.local. This is different than the type ClusterName below, which is in
	// reference to the Envoy cluster.
	Domain string
}

func (ms MeshService) String() string {
	// TODO(steeling): include the cluster here (use strings.Join())
	return fmt.Sprintf("%s%s%s", ms.Namespace, namespaceNameSeparator, ms.Name)
}

// TODO(steeling) we may want to allow a cert per cluster, but for now the Cert is often generated from the service
// account, which is not cluster scoped, so we're naming it based it on the service, unscoped to cluster.
func (ms MeshService) UnscopedName() string {
	return fmt.Sprintf("%s%s%s", ms.Namespace, namespaceNameSeparator, ms.Name)
}

// ClusterName is a type for a service name
type ClusterName string

// String returns the given ClusterName type as a string
func (c ClusterName) String() string {
	return string(c)
}

// WeightedCluster is a struct of a cluster and is weight that is backing a service
type WeightedCluster struct {
	ClusterName ClusterName `json:"cluster_name:omitempty"`
	Weight      int         `json:"weight:omitempty"`
}
