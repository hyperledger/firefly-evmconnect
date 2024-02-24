package metrics

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/metric"
	"github.com/hyperledger/firefly-evmconnect/internal/evmconfig"
	"github.com/hyperledger/firefly-transaction-manager/pkg/txhandler"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsEvmManagerComponentName = "evmconnect"

// REST api-server and transaction handler are sub-subsystem
var metricsTransactionHandlerSubsystemName = "th"
var metricsRESTAPIServerSubSystemName = "api_server_rest"

var mutex = &sync.Mutex{}

type metricsManager struct {
	ctx                     context.Context
	metricsEnabled          bool
	metricsRegistry         metric.MetricsRegistry
	txHandlerMetricsManager metric.MetricsManager
	timeMap                 map[string]time.Time
}

type Metrics interface {
	IsMetricsEnabled() bool

	// HTTPHandler returns the HTTP handler of this metrics registry
	HTTPHandler() http.Handler

	//Get the Api middleware and return a handler instace for the middleware
	GetAPIServerRESTHTTPMiddleware() func(next http.Handler) http.Handler

	// functions for transaction handler to define and emmit metrics
	TransactionHandlerMetrics
}

func NewMetricsManager(ctx context.Context) Metrics {
	metricsRegistry := metric.NewPrometheusMetricsRegistry(metricsEvmManagerComponentName)
	txHandlerMetricsManager, _ := metricsRegistry.NewMetricsManagerForSubsystem(ctx, metricsRESTAPIServerSubSystemName)
	_ = metricsRegistry.NewHTTPMetricsInstrumentationsForSubsystem(
		ctx,
		metricsRESTAPIServerSubSystemName,
		true,
		prometheus.DefBuckets,
		map[string]string{},
	)
	mm := &metricsManager{
		ctx:                     ctx,
		metricsEnabled:          config.GetBool(evmconfig.MetricsEnabled),
		timeMap:                 make(map[string]time.Time),
		metricsRegistry:         metricsRegistry,
		txHandlerMetricsManager: txHandlerMetricsManager,
	}
	return mm
}

func (mm *metricsManager) IsMetricsEnabled() bool {
	return mm.metricsEnabled
}

func (mm *metricsManager) HTTPHandler() http.Handler {
	httpMiddleware, _ := mm.metricsRegistry.HTTPHandler(mm.ctx, promhttp.HandlerOpts{})
	return httpMiddleware
}

// Transaction handler metrics are defined and emitted by transaction handlers
type TransactionHandlerMetrics interface {
	txhandler.TransactionMetrics
}

func (mm *metricsManager) GetAPIServerRESTHTTPMiddleware() func(next http.Handler) http.Handler {
	httpMiddleware, _ := mm.metricsRegistry.GetHTTPMetricsInstrumentationsMiddlewareForSubsystem(mm.ctx, metricsRESTAPIServerSubSystemName)
	return httpMiddleware
}

func (mm *metricsManager) InitTxHandlerCounterMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewCounterMetric(ctx, metricName, helpText, withDefaultLabels)
	}
}

func (mm *metricsManager) InitTxHandlerCounterMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewCounterMetricWithLabels(ctx, metricName, helpText, labelNames, withDefaultLabels)
	}
}

func (mm *metricsManager) InitTxHandlerGaugeMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewGaugeMetric(ctx, metricName, helpText, withDefaultLabels)
	}
}
func (mm *metricsManager) InitTxHandlerGaugeMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewGaugeMetricWithLabels(ctx, metricName, helpText, labelNames, withDefaultLabels)
	}
}
func (mm *metricsManager) InitTxHandlerHistogramMetric(ctx context.Context, metricName string, helpText string, buckets []float64, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewHistogramMetric(ctx, metricName, helpText, buckets, withDefaultLabels)
	}
}
func (mm *metricsManager) InitTxHandlerHistogramMetricWithLabels(ctx context.Context, metricName string, helpText string, buckets []float64, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewHistogramMetricWithLabels(ctx, metricName, helpText, buckets, labelNames, withDefaultLabels)
	}
}
func (mm *metricsManager) InitTxHandlerSummaryMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewSummaryMetric(ctx, metricName, helpText, withDefaultLabels)
	}
}
func (mm *metricsManager) InitTxHandlerSummaryMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.NewSummaryMetricWithLabels(ctx, metricName, helpText, labelNames, withDefaultLabels)
	}
}

// functions for use existing metrics
func (mm *metricsManager) SetTxHandlerGaugeMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.SetGaugeMetric(ctx, metricName, number, defaultLabels)
	}
}
func (mm *metricsManager) SetTxHandlerGaugeMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.SetGaugeMetricWithLabels(ctx, metricName, number, labels, defaultLabels)
	}
}

func (mm *metricsManager) IncTxHandlerCounterMetric(ctx context.Context, metricName string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.IncCounterMetric(ctx, metricName, defaultLabels)
	}
}
func (mm *metricsManager) IncTxHandlerCounterMetricWithLabels(ctx context.Context, metricName string, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.IncCounterMetricWithLabels(ctx, metricName, labels, defaultLabels)
	}
}
func (mm *metricsManager) ObserveTxHandlerHistogramMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.ObserveHistogramMetric(ctx, metricName, number, defaultLabels)
	}
}
func (mm *metricsManager) ObserveTxHandlerHistogramMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.ObserveHistogramMetricWithLabels(ctx, metricName, number, labels, defaultLabels)
	}
}

func (mm *metricsManager) ObserveTxHandlerSummaryMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.ObserveSummaryMetric(ctx, metricName, number, defaultLabels)
	}
}
func (mm *metricsManager) ObserveTxHandlerSummaryMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.txHandlerMetricsManager.ObserveSummaryMetricWithLabels(ctx, metricName, number, labels, defaultLabels)
	}
}
