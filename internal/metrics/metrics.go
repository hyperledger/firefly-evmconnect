package metrics

import (
	"context"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/metric"
	"github.com/hyperledger/firefly-evmconnect/internal/evmconfig"
	"github.com/prometheus/client_golang/prometheus"
)

const metricsEvmManagerComponentName = "evmconnect"

// REST api-server and transaction handler are sub-subsystem
var metricsTransactionHandlerSubsystemName = "evm"
var metricsRESTAPIServerSubSystemName = "api_server_rest"

type EvmMetricsManager struct {
	ctx                      context.Context
	metricsEnabled           bool
	metricsRegistry          metric.MetricsRegistry
	EvmHandlerMetricsManager metric.MetricsManager
	timeMap                  map[string]time.Time
}

type EvmMetrics interface {
	IsMetricsEnabled() bool

	// functions for Evm transaction handlers to define and emmit metrics
	TransactionHandlerMetrics
}

func NewMetricsManager(ctx context.Context) EvmMetrics {
	metricsRegistry := metric.NewPrometheusMetricsRegistry(metricsEvmManagerComponentName)
	EvmHandlerMetricsManager, _ := metricsRegistry.NewMetricsManagerForSubsystem(ctx, metricsRESTAPIServerSubSystemName)
	_ = metricsRegistry.NewHTTPMetricsInstrumentationsForSubsystem(
		ctx,
		metricsRESTAPIServerSubSystemName,
		true,
		prometheus.DefBuckets,
		map[string]string{},
	)
	mm := &EvmMetricsManager{
		ctx:                      ctx,
		metricsEnabled:           config.GetBool(evmconfig.MetricsEnabled),
		timeMap:                  make(map[string]time.Time),
		metricsRegistry:          metricsRegistry,
		EvmHandlerMetricsManager: EvmHandlerMetricsManager,
	}
	return mm
}

func (mm *EvmMetricsManager) IsMetricsEnabled() bool {
	return mm.metricsEnabled
}

// Transaction handler metrics are defined and emitted by transaction handlers
type TransactionHandlerMetrics interface {
	EvmTransactionHandlerMetrics
}

func (mm *EvmMetricsManager) InitEvmHandlerCounterMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewCounterMetric(ctx, metricName, helpText, withDefaultLabels)
	}
}

func (mm *EvmMetricsManager) InitEvmHandlerCounterMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewCounterMetricWithLabels(ctx, metricName, helpText, labelNames, withDefaultLabels)
	}
}

func (mm *EvmMetricsManager) InitEvmHandlerGaugeMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewGaugeMetric(ctx, metricName, helpText, withDefaultLabels)
	}
}
func (mm *EvmMetricsManager) InitEvmHandlerGaugeMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewGaugeMetricWithLabels(ctx, metricName, helpText, labelNames, withDefaultLabels)
	}
}
func (mm *EvmMetricsManager) InitEvmHandlerHistogramMetric(ctx context.Context, metricName string, helpText string, buckets []float64, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewHistogramMetric(ctx, metricName, helpText, buckets, withDefaultLabels)
	}
}
func (mm *EvmMetricsManager) InitEvmHandlerHistogramMetricWithLabels(ctx context.Context, metricName string, helpText string, buckets []float64, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewHistogramMetricWithLabels(ctx, metricName, helpText, buckets, labelNames, withDefaultLabels)
	}
}
func (mm *EvmMetricsManager) InitEvmHandlerSummaryMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewSummaryMetric(ctx, metricName, helpText, withDefaultLabels)
	}
}
func (mm *EvmMetricsManager) InitEvmHandlerSummaryMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.NewSummaryMetricWithLabels(ctx, metricName, helpText, labelNames, withDefaultLabels)
	}
}

// functions for use existing metrics
func (mm *EvmMetricsManager) SetEvmHandlerGaugeMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.SetGaugeMetric(ctx, metricName, number, defaultLabels)
	}
}
func (mm *EvmMetricsManager) SetEvmHandlerGaugeMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.SetGaugeMetricWithLabels(ctx, metricName, number, labels, defaultLabels)
	}
}

func (mm *EvmMetricsManager) IncEvmHandlerCounterMetric(ctx context.Context, metricName string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.IncCounterMetric(ctx, metricName, defaultLabels)
	}
}
func (mm *EvmMetricsManager) IncEvmHandlerCounterMetricWithLabels(ctx context.Context, metricName string, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.IncCounterMetricWithLabels(ctx, metricName, labels, defaultLabels)
	}
}
func (mm *EvmMetricsManager) ObserveEvmHandlerHistogramMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.ObserveHistogramMetric(ctx, metricName, number, defaultLabels)
	}
}
func (mm *EvmMetricsManager) ObserveEvmHandlerHistogramMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.ObserveHistogramMetricWithLabels(ctx, metricName, number, labels, defaultLabels)
	}
}

func (mm *EvmMetricsManager) ObserveEvmHandlerSummaryMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.ObserveSummaryMetric(ctx, metricName, number, defaultLabels)
	}
}
func (mm *EvmMetricsManager) ObserveEvmHandlerSummaryMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) {
	if mm.metricsEnabled {
		mm.EvmHandlerMetricsManager.ObserveSummaryMetricWithLabels(ctx, metricName, number, labels, defaultLabels)
	}
}
