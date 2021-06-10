// Package service models an instance of a service managed by OSM controller and utility routines associated with it.
package service

import (
	"fmt"
	"strings"
)

const (
	// namespaceNameSeparator used upon marshalling/unmarshalling MeshService to a string
	// or viceversa
	namespaceNameSeparator = "/"
)

type Locality int

const (
	LocalNS Locality = iota
	LocalCluster
	RemoteCluster
)

// MeshService is the struct defining a service (Kubernetes or otherwise) within a service mesh.
type MeshService struct {
	// If the service resides on a Kubernetes service, this would be the Kubernetes namespace.
	Namespace string

	// The name of the service
	Name string

	Cluster string
}

func (ms MeshService) String() string {
	return fmt.Sprintf("%s%s%s", ms.Namespace, namespaceNameSeparator, ms.Name)
}

// FullName is similar to String(), but uses a dot separator and is in a different order.
func (ms MeshService) FullName() string {
	return strings.Join([]string{ms.Name, ms.Namespace}, ".")
}

func (ms MeshService) Local() bool {
	return ms.Cluster == "local"
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
