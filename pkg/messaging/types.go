// Package messaging implements the messaging infrastructure between different
// components within the control plane.
package messaging

import (
	"time"

	"github.com/cskr/pubsub"
	"k8s.io/client-go/util/workqueue"

	"github.com/openservicemesh/osm/pkg/k8s/events"
	"github.com/openservicemesh/osm/pkg/logger"
)

var (
	log = logger.New("message-broker")
)

// Broker implements the message broker functionality
type Broker struct {
	queue                          workqueue.RateLimitingInterface
	proxyUpdatePubSub              *pubsub.PubSub
	proxyUpdateCh                  chan proxyUpdateEvent
	kubeEventPubSub                *pubsub.PubSub
	certPubSub                     *pubsub.PubSub
	totalQEventCount               uint64
	totalQProxyEventCount          uint64
	totalDispatchedProxyEventCount uint64
}

// proxyUpdateEvent specifies the PubSubMessage and topic for an event that
// results in a proxy config update
type proxyUpdateEvent struct {
	msg   events.PubSubMessage
	topic string
}

// EventType is the type of event we have received from Kubernetes
type EventType string

func (et EventType) String() string {
	return string(et)
}

const (
	// AddEvent is a type of a Kubernetes API event.
	AddEvent EventType = "ADD"

	// UpdateEvent is a type of a Kubernetes API event.
	UpdateEvent EventType = "UPDATE"

	// DeleteEvent is a type of a Kubernetes API event.
	DeleteEvent EventType = "DELETE"
)

const (
	// DefaultKubeEventResyncInterval is the default resync interval for k8s events
	// This is set to 0 because we do not need resyncs from k8s client, and have our
	// own Ticker to turn on periodic resyncs.
	DefaultKubeEventResyncInterval = 0 * time.Second
)
