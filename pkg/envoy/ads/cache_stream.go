package ads

import (
	"context"
	"fmt"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/openservicemesh/osm/pkg/envoy"
)

// ServeResources stores a group of resources as a new Snapshot with a new version in the cache.
// It also runs a consistency check on the snapshot (will warn if there are missing resources referenced in
// the snapshot)
func (s *Server) ServeResources(ctx context.Context, proxy *envoy.Proxy, snapshotResources map[string][]types.Resource) error {
	uuid := proxy.UUID.String()

	s.configVerMutex.Lock()
	s.configVersion[uuid]++
	configVersion := s.configVersion[uuid]
	s.configVerMutex.Unlock()

	snapshot, err := cache.NewSnapshot(fmt.Sprintf("%d", configVersion), snapshotResources)
	if err != nil {
		return err
	}

	if err := snapshot.Consistent(); err != nil {
		return err
	}

	return s.snapshotCache.SetSnapshot(context.TODO(), uuid, snapshot)
}
