package debugger

import (
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	tassert "github.com/stretchr/testify/assert"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/tests"
)

// Tests getMonitoredNamespaces through HTTP handler returns a the list of monitored namespaces
func TestMonitoredNamespaceHandler(t *testing.T) {
	assert := tassert.New(t)

	mock := catalog.NewMockMeshCataloger(gomock.NewController(t))

	ds := DebugConfig{
		meshCatalog: mock,
	}
	monitoredNamespacesHandler := ds.getMonitoredNamespacesHandler()

	uniqueNs := tests.GetUnique([]string{
		tests.BookbuyerService.Namespace,   // default
		tests.BookstoreV1Service.Namespace, // default
	})

	mock.EXPECT().ListNamespaces().Return(uniqueNs, nil)

	responseRecorder := httptest.NewRecorder()
	monitoredNamespacesHandler.ServeHTTP(responseRecorder, nil)
	actualResponseBody := responseRecorder.Body.String()
	expectedResponseBody := `{"namespaces":["default"]}`
	assert.Equal(expectedResponseBody, actualResponseBody, "Actual value did not match expectations:\n%s", actualResponseBody)
}
