package catalog

import (
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/endpoint"
	"github.com/openservicemesh/osm/pkg/ingress"
	k8s "github.com/openservicemesh/osm/pkg/kubernetes"
	"github.com/openservicemesh/osm/pkg/policy"
	"github.com/openservicemesh/osm/pkg/smi"
)

// NewMeshCatalog creates a new service catalog
func NewMeshCatalog(kubeController k8s.Controller, meshSpec smi.MeshSpec, certManager certificate.Manager, ingressMonitor ingress.Monitor, policyController policy.Controller, stop <-chan struct{}, endpointsProviders ...endpoint.Provider) *MeshCatalog {
	log.Info().Msg("Create a new Service MeshCatalog.")
	mc := MeshCatalog{
		endpointsProviders: endpointsProviders,
		meshSpec:           meshSpec,
		certManager:        certManager,
		ingressMonitor:     ingressMonitor,
		policyController:   policyController,

		kubeController: kubeController,
	}

	go mc.dispatcher()

	return &mc
}

// GetKubeController returns the kube controller instance handling the current cluster
func (mc *MeshCatalog) GetKubeController() k8s.Controller {
	return mc.kubeController
}
