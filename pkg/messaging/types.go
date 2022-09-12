// Package messaging implements the messaging infrastructure between different
// components within the control plane.
package messaging

import (
	"github.com/cskr/pubsub"

	"github.com/openservicemesh/osm/pkg/logger"
)

var (
	log = logger.New("message-broker")
)

// Broker implements the message broker functionality
type Broker struct {
	proxyUpdatePubSub              *pubsub.PubSub
	kubeEventPubSub                *pubsub.PubSub
	totalQEventCount               uint64
	totalQProxyEventCount          uint64
	totalDispatchedProxyEventCount uint64
}

const (
	// ProxyUpdateTopic is the topic used to send proxy updates
	ProxyUpdateTopic = "proxy-update"
)
