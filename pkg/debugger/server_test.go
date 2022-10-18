package debugger

import (
	"testing"
	"time"

	"github.com/openservicemesh/osm/pkg/compute"
	"github.com/openservicemesh/osm/pkg/messaging"

	"github.com/golang/mock/gomock"
	tassert "github.com/stretchr/testify/assert"
	testclient "k8s.io/client-go/kubernetes/fake"

	"github.com/openservicemesh/osm/pkg/catalog"
	tresorFake "github.com/openservicemesh/osm/pkg/certificate/providers/tresor/fake"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/k8s"
)

// Tests GetHandlers returns the expected debug endpoints and non-nil handlers
func TestGetHandlers(t *testing.T) {
	assert := tassert.New(t)
	mockCtrl := gomock.NewController(t)

	cm := tresorFake.NewFake(time.Hour)
	mockXdsDebugger := NewMockXDSDebugger(mockCtrl)
	client := testclient.NewSimpleClientset()
	mockKubeController := k8s.NewMockController(mockCtrl)
	proxyRegistry := registry.NewProxyRegistry()
	mock := compute.NewMockInterface(mockCtrl)
	stop := make(chan struct{})
	meshCatalog := catalog.NewMeshCatalog(
		mock,
		tresorFake.NewFake(time.Hour),
		stop,
		messaging.NewBroker(stop),
	)

	ds := NewDebugConfig(cm,
		mockXdsDebugger,
		meshCatalog,
		proxyRegistry,
		nil,
		client,
		mockKubeController,
		nil)

	handlers := ds.GetHandlers()

	debugEndpoints := []string{
		"/debug/certs",
		"/debug/xds",
		"/debug/proxy",
		"/debug/policies",
		"/debug/config",
		"/debug/namespaces",
		// Pprof handlers
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/profile",
		"/debug/pprof/symbol",
		"/debug/pprof/trace",
	}

	for _, endpoint := range debugEndpoints {
		handler, found := handlers[endpoint]
		assert.True(found)
		assert.NotNil(handler)
	}
}
