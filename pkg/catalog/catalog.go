package catalog

import (
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/compute"
	"github.com/openservicemesh/osm/pkg/smi"
)

// NewMeshCatalog creates a new service catalog
func NewMeshCatalog(meshSpec smi.MeshSpec, certManager *certificate.Manager, computeInterface compute.Interface) *MeshCatalog {
	return &MeshCatalog{
		Interface:   computeInterface,
		meshSpec:    meshSpec,
		certManager: certManager,
	}
}

// GetTrustDomain returns the currently configured trust domain, ie: cluster.local
func (mc *MeshCatalog) GetTrustDomain() string {
	return mc.certManager.GetTrustDomain()
}
