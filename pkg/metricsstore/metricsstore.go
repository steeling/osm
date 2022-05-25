// Package metricsstore implements a Prometheus metrics store for OSM's control plane metrics.
package metricsstore

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsRootNamespace is the root namespace for all the metrics emitted.
// Ex: osm_<metric-name>
const metricsRootNamespace = "osm"

// MetricsStore is a type that provides functionality related to metrics
type MetricsStore struct {
	// Define metrics by their category below ----------------------

	/*
	 * K8s metrics
	 */
	// K8sAPIEventCounter is the metric counter for the number of K8s API events
	K8sAPIEventCounter *prometheus.CounterVec

	/*
	 * Resource metrics
	 */
	// MonitoredNamespaceCounter is the metric counter for the total number of monitored namespaces in the mesh
	MonitoredNamespaceCounter prometheus.Gauge

	/*
	 * Proxy metrics
	 */
	// ProxyConnectCount is the metric for the total number of proxies connected to the controller
	ProxyConnectCount prometheus.Gauge

	// ProxyReconnectCount is the metric for the total reconnects from known proxies to the controller
	ProxyReconnectCount prometheus.Counter

	// ProxyConfigUpdateTime is the histogram to track time spent for proxy configuration and its occurrences
	ProxyConfigUpdateTime *prometheus.HistogramVec

	// ProxyBroadcastEventCounter is the metric for the total number of ProxyBroadcast events published
	ProxyBroadcastEventCount prometheus.Counter

	// ProxyResponseSendSuccessCount is the metric for the total number of successful responses sent to the proxies
	ProxyResponseSendSuccessCount *prometheus.CounterVec

	// ProxyResponseSendErrorCount is the metric for the total number of errors encountered while sending responses to proxies
	ProxyResponseSendErrorCount *prometheus.CounterVec

	// ProxyXDSRequestCount counts XDS requests made by proxies
	ProxyXDSRequestCount *prometheus.CounterVec

	// ProxyMaxConnectionsRejected counts the number of proxy connections
	// rejected due to the max connections limit being reached
	ProxyMaxConnectionsRejected prometheus.Counter

	// AdmissionWebhookResponseTotal counts the number of webhook responses
	// generated for both validating and mutating webhooks
	AdmissionWebhookResponseTotal *prometheus.CounterVec

	// ConversionWebhookResponseTotal counts the resources converted by
	// conversion webhooks
	ConversionWebhookResourceTotal *prometheus.CounterVec

	/*
	 * Certificate metrics
	 */
	// CertIssuedCount is the metric counter for the number of certificates issued
	CertIssuedCount prometheus.Counter

	// CertXdsIssuedCounter the histogram to track the time to issue a certificates
	CertIssuedTime *prometheus.HistogramVec

	/*
	 * ErrCode metrics
	 */
	// ErrCodeCounter is the metric counter for the number of errcodes generated by OSM
	ErrCodeCounter *prometheus.CounterVec

	// HTTPResponseTotal is the metric counter for the number of HTTP responses
	// sent by OSM's HTTP handlers
	HTTPResponseTotal *prometheus.CounterVec

	// HTTPResponseDuration is the histogram to track the time to respond to
	// HTTP requests
	HTTPResponseDuration *prometheus.HistogramVec

	// FeatureFlagEnabled represents whether each feature flag is enabled (1) or
	// disabled (0)
	FeatureFlagEnabled *prometheus.GaugeVec

	// VersionInfo contains the static version information of OSM as labels. The gauge is always set to 1.
	VersionInfo *prometheus.GaugeVec

	// EventsQueued represents the number of events seen but not yet processed
	// by the control plane
	EventsQueued prometheus.Gauge

	/*
	 * MetricsStore internals should be defined below --------------
	 */
	registry *prometheus.Registry
}

var defaultMetricsStore MetricsStore

// DefaultMetricsStore is the default metrics store
var DefaultMetricsStore = &defaultMetricsStore

func init() {
	/*
	 * K8s metrics
	 */
	defaultMetricsStore.K8sAPIEventCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsRootNamespace,
			Subsystem: "k8s",
			Name:      "api_event_count",
			Help:      "Represents the number of events received from the Kubernetes API Server",
		},
		[]string{"type", "namespace"},
	)

	/*
	 * Resource metrics
	 */
	defaultMetricsStore.MonitoredNamespaceCounter = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "resource",
		Name:      "namespace_count",
		Help:      "Represents the number of monitored namespaces in the service mesh",
	})

	/*
	 * Proxy metrics
	 */
	defaultMetricsStore.ProxyConnectCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "proxy",
		Name:      "connect_count",
		Help:      "Represents the number of proxies connected to OSM controller",
	})

	defaultMetricsStore.ProxyReconnectCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "proxy",
		Name:      "reconnect_count",
		Help:      "Represents the number of reconnects from known proxies to OSM controller",
	})

	defaultMetricsStore.ProxyResponseSendSuccessCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "proxy",
		Name:      "response_send_success_count",
		Help:      "Represents the number of responses successfully sent to proxies",
	}, []string{"proxy_name", "type"})

	defaultMetricsStore.ProxyResponseSendErrorCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "proxy",
		Name:      "response_send_error_count",
		Help:      "Represents the number of responses that errored when being set to proxies",
	}, []string{"proxy_name", "type"})

	defaultMetricsStore.ProxyConfigUpdateTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsRootNamespace,
			Subsystem: "proxy",
			Name:      "config_update_time",
			Buckets:   []float64{.1, .25, .5, 1, 2.5, 5, 10, 20, 40, 90},
			Help:      "Histogram to track time spent for proxy configuration",
		},
		[]string{
			"resource_type", // identifies a typeURI resource
			"success",       // further labels if the operation succeeded or not
		})

	defaultMetricsStore.ProxyBroadcastEventCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "proxy",
		Name:      "broadcast_event_count",
		Help:      "Represents the number of ProxyBroadcast events published by the OSM controller",
	})

	defaultMetricsStore.ProxyXDSRequestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "proxy",
		Name:      "xds_request_count",
		Help:      "Represents the number of XDS requests made by proxies",
	}, []string{"proxy_name", "type"})

	defaultMetricsStore.ProxyMaxConnectionsRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "proxy",
		Name:      "max_connections_rejected",
		Help:      "Represents the number of proxy connections rejected due to the configured max connections limit",
	})

	defaultMetricsStore.AdmissionWebhookResponseTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Name:      "admission_webhook_response_total",
		Help:      "Counter for responses sent by admission webhooks",
	}, []string{"kind", "success"})

	defaultMetricsStore.ConversionWebhookResourceTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Name:      "conversion_webhook_resource_total",
		Help:      "Counter for resources converted by conversion webhooks",
	}, []string{"kind", "from_version", "to_version", "success"})

	/*
	 * Certificate metrics
	 */
	defaultMetricsStore.CertIssuedCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Subsystem: "cert",
		Name:      "issued_count",
		Help:      "Represents the total number of XDS certificates issued to proxies",
	})

	defaultMetricsStore.CertIssuedTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsRootNamespace,
			Subsystem: "cert",
			Name:      "issued_time",
			Buckets:   []float64{.1, .25, .5, 1, 2.5, 5, 10, 20, 40, 90},
			Help:      "Histogram to track time spent to issue xds certificate",
		},
		[]string{})

	/*
	 * ErrCode metrics
	 */
	defaultMetricsStore.ErrCodeCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsRootNamespace,
			Subsystem: "error",
			Name:      "err_code_count",
			Help:      "Respesents the number of errcodes generated by OSM",
		},
		[]string{"err_code"},
	)

	defaultMetricsStore.HTTPResponseTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsRootNamespace,
		Name:      "http_response_total",
		Help:      "Counter of HTTP responses sent",
	}, []string{"code", "method", "path"})

	defaultMetricsStore.HTTPResponseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsRootNamespace,
		Name:      "http_response_duration",
		Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		Help:      "Duration in seconds of HTTP responses sent",
	}, []string{"code", "method", "path"})

	defaultMetricsStore.FeatureFlagEnabled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsRootNamespace,
		Name:      "feature_flag_enabled",
		Help:      "Represents whether a feature flag is enabled (1) or disabled (0)",
	}, []string{"feature_flag"})

	defaultMetricsStore.VersionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsRootNamespace,
		Name:      "version_info",
		Help:      "Contains the static information denoting the version of this OSM instance",
	}, []string{"version", "build_date", "git_commit"})

	defaultMetricsStore.EventsQueued = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsRootNamespace,
		Name:      "events_queued",
		Help:      "Number of events seen but not yet processed by the control plane",
	})

	defaultMetricsStore.registry = prometheus.NewRegistry()
}

// Start store
func (ms *MetricsStore) Start(cs ...prometheus.Collector) {
	ms.registry.MustRegister(cs...)
}

// Stop store
func (ms *MetricsStore) Stop(cs ...prometheus.Collector) {
	for _, c := range cs {
		ms.registry.Unregister(c)
	}
}

// Handler return the registry
func (ms *MetricsStore) Handler() http.Handler {
	return promhttp.InstrumentMetricHandler(
		ms.registry,
		promhttp.HandlerFor(ms.registry, promhttp.HandlerOpts{}),
	)
}

// Contains returns whether or not the given string appears in the store's HTTP
// handler response
func (ms *MetricsStore) Contains(metric string) bool {
	req := httptest.NewRequest("GET", "http://this.doesnt/matter", nil)
	w := httptest.NewRecorder()
	ms.Handler().ServeHTTP(w, req)
	res := w.Body.String()

	return strings.Contains(res, metric)
}

// AddHTTPMetrics wraps the given handler with one that tracks HTTP metrics for
// response counts and durations
func AddHTTPMetrics(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labels := prometheus.Labels{"path": r.URL.Path}
		promhttp.InstrumentHandlerDuration(DefaultMetricsStore.HTTPResponseDuration.MustCurryWith(labels),
			promhttp.InstrumentHandlerCounter(DefaultMetricsStore.HTTPResponseTotal.MustCurryWith(labels), h)).
			ServeHTTP(w, r)
	})
}
