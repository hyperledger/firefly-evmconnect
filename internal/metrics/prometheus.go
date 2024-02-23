package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	muxprom "gitlab.com/hfuss/mux-prometheus/pkg/middleware"
)

var regMux sync.Mutex
var registry *prometheus.Registry
var evmInstrumentation *muxprom.Instrumentation

// Registry returns FireFly's customized Prometheus registry
func Registry() *prometheus.Registry {
	if registry == nil {
		initMetricsCollectors()
		registry = prometheus.NewRegistry()
		registerMetricsCollectors()
	}
	return registry
}

// GetEvmServerInstrumentation returns the transaction server's Prometheus middleware, ensuring its metrics are never
// registered twice
func GetEvmServerInstrumentation() *muxprom.Instrumentation {
	regMux.Lock()
	defer regMux.Unlock()
	if evmInstrumentation == nil {
		evmInstrumentation = NewInstrumentation("ffevm")
	}
	return evmInstrumentation
}

func NewInstrumentation(subsystem string) *muxprom.Instrumentation {
	return muxprom.NewCustomInstrumentation(
		true,
		"ff_evmconnect",
		subsystem,
		prometheus.DefBuckets,
		map[string]string{},
		Registry(),
	)
}

// Clear will reset the Prometheus metrics registry and instrumentations, useful for testing
func Clear() {
	registry = nil
	evmInstrumentation = nil

}

func initMetricsCollectors() {
	InitEvmCustomMetrics()
}

func registerMetricsCollectors() {
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	RegsiterEvmCustomMetrics()
}
