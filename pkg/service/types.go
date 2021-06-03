// Package service models an instance of a service managed by OSM controller and utility routines associated with it.
package service

import (
	"strings"
)

const (
	// meshServicehSeparator used upon marshalling/unmarshalling MeshService to a string
	// or viceversa
	meshServicehSeparator = "/"
)

// MeshService is the struct defining a service (Kubernetes or otherwise) within a service mesh.
type MeshService struct {
	// If the service resides on a Kubernetes service, this would be the Kubernetes namespace.
	Namespace string

	// The name of the service
	Name string

	// The OSMCluster this service represents. If ommitted, it is treated as "local", or equivalently the MeshConfigs
	// Spec.ClusterID field. It does not directly impact the domain, but is set based on the annotations present in the
	// TrafficTarget and TrafficSplit objects.
	// * is a special value that means it will apply to all clusters, remote, local, and global.
	OSMCluster string
}

func (ms MeshService) String() string {
	return strings.Join([]string{ms.Namespace, ms.Name, ms.OSMCluster}, meshServicehSeparator)
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
