package catalog

import (
	"testing"

	tassert "github.com/stretchr/testify/assert"

	"github.com/openservicemesh/osm/pkg/featureflags"
	"github.com/openservicemesh/osm/pkg/identity"
)

func TestIsMultiClusterGateway(t *testing.T) {
	assert := tassert.New(t)
	mc := newFakeMeshCatalog()

	testCases := []struct {
		name  string
		svcID identity.ServiceIdentity
		want  bool
	}{
		{

			"multi cluster gateway",
			identity.K8sServiceAccount{Name: "gateway", Namespace: "-test-osm-namespace-"}.ToServiceIdentity(),
			true,
		},
		{
			"wrong namespace",
			identity.K8sServiceAccount{Name: "gateway", Namespace: "default"}.ToServiceIdentity(),
			false,
		},
		{
			"wrong name",
			identity.K8sServiceAccount{Name: "random", Namespace: "-test-osm-system"}.ToServiceIdentity(),
			false,
		},
	}
	featureflags.Features.MulticlusterMode = true
	assert.Equal("-test-osm-namespace-", mc.configurator.GetOSMNamespace())
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(tc.want, mc.IsMultiClusterGateway(tc.svcID), tc.name)
		})
	}
}
