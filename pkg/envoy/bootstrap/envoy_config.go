package bootstrap

import (
	xds_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	xds_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
)

// getProbeResources returns the listener and cluster objects that are statically configured to serve
// startup, readiness and liveness probes.
// These will not change during the lifetime of the Pod.
// If the original probe defined a TCPSocket action, listener and cluster objects are not configured
// to serve that probe.
func (b *Builder) getProbeResources() ([]*xds_listener.Listener, []*xds_cluster.Cluster, error) {
	// This slice is the list of listeners for liveness, readiness, startup IF these have been configured in the Pod Spec
	var listeners []*xds_listener.Listener
	var clusters []*xds_cluster.Cluster

	// Is there a liveness probe in the Pod Spec?
	if b.OriginalHealthProbes.Liveness != nil && !b.OriginalHealthProbes.Liveness.isTCPSocket {
		listener, err := getLivenessListener(b.OriginalHealthProbes.Liveness)
		if err != nil {
			log.Error().Err(err).Msgf("Error getting liveness listener")
			return nil, nil, err
		}
		listeners = append(listeners, listener)
		clusters = append(clusters, getLivenessCluster(b.OriginalHealthProbes.Liveness))
	}

	// Is there a readiness probe in the Pod Spec?
	if b.OriginalHealthProbes.Readiness != nil && !b.OriginalHealthProbes.Readiness.isTCPSocket {
		listener, err := getReadinessListener(b.OriginalHealthProbes.Readiness)
		if err != nil {
			log.Error().Err(err).Msgf("Error getting readiness listener")
			return nil, nil, err
		}
		listeners = append(listeners, listener)
		clusters = append(clusters, getReadinessCluster(b.OriginalHealthProbes.Readiness))
	}

	// Is there a startup probe in the Pod Spec?
	if b.OriginalHealthProbes.Startup != nil && !b.OriginalHealthProbes.Startup.isTCPSocket {
		listener, err := getStartupListener(b.OriginalHealthProbes.Startup)
		if err != nil {
			log.Error().Err(err).Msgf("Error getting startup listener")
			return nil, nil, err
		}
		listeners = append(listeners, listener)
		clusters = append(clusters, getStartupCluster(b.OriginalHealthProbes.Startup))
	}

	return listeners, clusters, nil
}
