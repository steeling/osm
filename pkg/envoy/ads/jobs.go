package ads

import (
	"fmt"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/openservicemesh/osm/pkg/envoy"
)

// proxyResponseJob is the worker pool job implementation for a Proxy response function
// It takes the parameters of `server.sendResponse` and allows to queue it as a job on a workerpool
type proxyResponseJob struct {
	proxy             *envoy.Proxy
	GenerateResources func(proxy *envoy.Proxy) (map[string][]types.Resource, error)
	ServeResources    func(map[string][]types.Resource) error
	done              chan struct{}
}

// Done returns the channel, which when closed, indicates the job has been finished.
func (job *proxyResponseJob) Done() chan struct{} {
	return job.done
}

// Run implementation for `server.sendResponse` job
func (job *proxyResponseJob) Run() {
	resources, err := job.GenerateResources(job.proxy)
	if err != nil {
		log.Error().Err(err).Str("proxy", job.proxy.String()).Msg("Error generating resources")
	}
	if err := job.ServeResources(resources); err != nil {
		log.Error().Err(err).Str("proxy", job.proxy.String()).Msg("Error serving resources")
	}
	close(job.done)
}

// JobName implementation for this job, for logging purposes
func (proxyJob *proxyResponseJob) JobName() string {
	return fmt.Sprintf("sendJob-%s", proxyJob.proxy.GetName())
}
