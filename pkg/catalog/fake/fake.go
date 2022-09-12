package fake

import (
	"time"

	"github.com/openservicemesh/osm/pkg/compute"

	"github.com/openservicemesh/osm/pkg/catalog"
	tresorFake "github.com/openservicemesh/osm/pkg/certificate/providers/tresor/fake"
	smiFake "github.com/openservicemesh/osm/pkg/smi/fake"
)

// NewFakeMeshCatalog creates a new struct implementing catalog.MeshCataloger interface used for testing.
func NewFakeMeshCatalog(provider compute.Interface) *catalog.MeshCatalog {
	meshSpec := smiFake.NewFakeMeshSpecClient()
	certManager := tresorFake.NewFake(1 * time.Hour)
	return catalog.NewMeshCatalog(meshSpec, certManager, provider)
}
