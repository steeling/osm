// Package bootstrap implements functionality related to Envoy's bootstrap config.
package bootstrap

import (
	xds_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/logger"
)

var log = logger.New("envoy/bootstrap")

// Config is the type used to represent the information needed to build the Envoy bootstrap config
type Builder struct {
	// XDSHost is the hostname of the XDS cluster to connect to
	XDSHost string

	// TLSMinProtocolVersion is the minimum supported TLS protocol version
	TLSMinProtocolVersion string

	// TLSMaxProtocolVersion is the maximum supported TLS protocol version
	TLSMaxProtocolVersion string

	// CipherSuites is the list of cipher that TLS 1.0-1.2 supports
	CipherSuites []string

	// ECDHCurves is the list of ECDH curves it supports
	ECDHCurves []string

	// The bootstrap Envoy config will be affected by the liveness, readiness, startup probes set on
	// the pod this Envoy is fronting.
	OriginalHealthProbes HealthProbes

	Certificate  *certificate.Certificate
	OSMNamespace string

	prevConfig *xds_bootstrap.Bootstrap
}
