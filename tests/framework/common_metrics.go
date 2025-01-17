package framework

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openservicemesh/osm/pkg/k8s"
)

var (
	errEmptyResult = fmt.Errorf("Empty result from prometheus")
)

// Prometheus is a simple handler to represent a target Prometheus endpoint to run queries against
type Prometheus struct {
	Client api.Client
	API    v1.API

	pfwd *k8s.PortForwarder
}

// Stop gracefully stops the port forwarding to Prometheus
func (p *Prometheus) Stop() {
	p.pfwd.Stop()
}

// VectorQuery runs a query at time <t>, expects single vector type and single result.
// Returns expected first and only <SampleValue> as a float64
// Returns 0 and err<Empty result from prometheus>, if no values are seen on prometheus (but query did succeed)
func (p *Prometheus) VectorQuery(query string, t time.Time) (float64, error) {
	modelValue, warn, err := p.API.Query(context.Background(), query, t)

	if err != nil {
		return 0, err
	}
	if len(warn) > 0 {
		fmt.Printf("Warnings: %v\n", warn)
	}
	switch {
	case modelValue.Type() == model.ValVector:
		vectorVal := modelValue.(model.Vector)
		if len(vectorVal) == 0 {
			return 0, errEmptyResult
		}
		return float64(vectorVal[0].Value), nil
	default:
		return 0, fmt.Errorf("Unknown model value type: %v", modelValue.Type().String())
	}
}

// GetNumEnvoysInMesh Gets the Number of in-mesh pods (or envoys) in the mesh as seen
// by prometheus at a certain point in time.
func (p *Prometheus) GetNumEnvoysInMesh(t time.Time) (int, error) {
	queryString := "sum(osm_k8s_api_event_count{type=\"pod-added\"}) by (source_pod_name) OR on() vector(0) - sum(osm_k8s_api_event_count{type=\"pod-deleted\"})"
	val, err := p.VectorQuery(queryString, t)
	if err == errEmptyResult {
		return 0, nil
	}
	return int(val), err
}

// GetMemRSSforContainer returns RSS memory footprint for a given NS/podname/containerName
// at a certain point in time
func (p *Prometheus) GetMemRSSforContainer(ns string, podName string, containerName string, t time.Time) (float64, error) {
	queryString := fmt.Sprintf(
		"container_memory_rss{namespace='%s', pod='%s', container='%s'}",
		ns,
		podName,
		containerName)

	return p.VectorQuery(queryString, t)
}

// GetCPULoadAvgforContainer returns CPU load average for a period <duration> just before time <t>
func (p *Prometheus) GetCPULoadAvgforContainer(ns string, podName string, containerName string,
	period time.Duration, t time.Time) (float64, error) {
	queryString := fmt.Sprintf(
		"rate(container_cpu_usage_seconds_total{namespace='%s', pod='%s', container='%s'}[%ds])",
		ns,
		podName,
		containerName,
		int(period.Seconds()))

	return p.VectorQuery(queryString, t)
}

// GetCPULoadsForContainer convenience wrapper to get 1m, 5m and 15m cpu loads for a resource
func (p *Prometheus) GetCPULoadsForContainer(ns string, podName string, containerName string, t time.Time) (float64, float64, float64, error) {
	timeBuckets := []time.Duration{1 * time.Minute, 5 * time.Minute, 15 * time.Minute}
	var loads []float64

	for _, bucketTime := range timeBuckets {
		val, err := p.GetCPULoadAvgforContainer(ns, podName, containerName, bucketTime, t)
		if err != nil {
			return 0, 0, 0, err
		}
		loads = append(loads, val)
	}

	return loads[0], loads[1], loads[2], nil
}

/// --- Grafana Rendering API below ---

// Grafana is a simple handler to represent a target Grafana endpoint to run queries against
type Grafana struct {
	Schema   string
	Hostname string
	Port     uint16
	User     string
	Password string

	pfwd *k8s.PortForwarder
}

// Stop gracefully stops the port forwarding to Grafana
func (g *Grafana) Stop() {
	g.pfwd.Stop()
}

// PanelPNGSnapshot takes a snapshot from a Grafana dashboard or panel
// and saves it in local in <filename> in png format, using it's remote rendering HTTP API.
func (g *Grafana) PanelPNGSnapshot(dashboard string, panelID int, fromMinutes int, saveFilepath string) error {
	// Grafana render URL

	renderURL, _ := url.Parse(fmt.Sprintf("%s://%s:%d/render/d-solo/%s",
		g.Schema,
		g.Hostname,
		g.Port,
		dashboard))

	renderURL.User = url.UserPassword(g.User, g.Password)

	// Create queries to assign query values
	query := make(url.Values)

	// Org Id is internal to grafana to address admin organizations
	query.Add("orgId", "1")

	// Graphing from <fromMinutes> to now
	query.Add("from", fmt.Sprintf("now-%dm", fromMinutes))
	query.Add("to", "now")

	// size of the drawing, in pixels
	query.Add("width", "1000")
	query.Add("height", "500")

	// panel ID, which panel are we interested in (cpu, mem, etc.)
	query.Add("panelId", fmt.Sprintf("%d", panelID))

	// Add all query parameters to url
	renderURL.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", renderURL.String(), nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Printf("Err closing %v", err)
		}
	}()

	saveFilepath = fmt.Sprintf("%s%s", saveFilepath, ".png")
	out, err := os.Create(filepath.Clean(saveFilepath))
	if err != nil {
		return err
	}
	defer func() {
		err := out.Close()
		if err != nil {
			fmt.Printf("Err closing %v", err)
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Saved panel snapshot as %s\n", saveFilepath)

	return nil
}

// GetEnvoyMetric returns the metrics for the given pod query regex matchers.
// The returned list is the same size as the input list and the results are
// indexed per the query index in the input string.
// For e.g. if the query=[`.*over_limit.*`, `tls_inspector.*alpn_found.*`],
// the output ["5", "6"] implies metrics matching the queries are:
// `.*over_limit.*`: 5
// `tls_inspector.*alpn_found.*`: 6
func (td *OsmTestData) GetEnvoyMetric(pod types.NamespacedName, queryMatchers []string) ([]int, error) {
	stdout, stderr, err := Td.RunLocal(filepath.FromSlash("../../bin/osm"), "proxy", "get", "stats", pod.Name, "--namespace", pod.Namespace)
	if err != nil {
		time.Sleep(1 * time.Minute)
		return nil, fmt.Errorf("could not get client stats, stderr=%s, err=%w", stderr, err)
	}

	metrics := make([]int, len(queryMatchers))
	for i, key := range queryMatchers {
		re := regexp.MustCompile(key)
		matches := re.FindStringSubmatch(stdout.String())
		if len(matches) > 0 {
			// If multiple matches exist, pick the first match
			// It's the caller's responsibility to provide the most
			// precise matcher for the metric
			m := strings.SplitN(matches[0], ":", 2)
			val, err := strconv.Atoi(strings.TrimSpace(m[1]))
			if err != nil {
				return nil, fmt.Errorf("error getting numeric metric for query %s: %w", key, err)
			}
			metrics[i] = val
		}
	}

	return metrics, nil
}

// ResetEnvoyStats resets the Envoy stats counters for the given pod
func (td *OsmTestData) ResetEnvoyStats(pod types.NamespacedName) error {
	_, stderr, err := Td.RunLocal(filepath.FromSlash("../../bin/osm"), "proxy", "set", "reset_counters", pod.Name, "--namespace", pod.Namespace)
	if err != nil {
		time.Sleep(1 * time.Minute)
		return fmt.Errorf("could not get client stats, stderr=%s, err=%w", stderr, err)
	}
	return nil
}
