package metrics

import (
	"context"

	"github.com/hyperledger/firefly-common/pkg/metric"
)

type EvmTransactionHandlerMetrics interface {
	//intializing and emmiting metrics
	InitEvmHandlerCounterMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool)
	InitEvmHandlerCounterMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool)
	InitEvmHandlerGaugeMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool)
	InitEvmHandlerGaugeMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool)
	InitEvmHandlerHistogramMetric(ctx context.Context, metricName string, helpText string, buckets []float64, withDefaultLabels bool)
	InitEvmHandlerHistogramMetricWithLabels(ctx context.Context, metricName string, helpText string, buckets []float64, labelNames []string, withDefaultLabels bool)
	InitEvmHandlerSummaryMetric(ctx context.Context, metricName string, helpText string, withDefaultLabels bool)
	InitEvmHandlerSummaryMetricWithLabels(ctx context.Context, metricName string, helpText string, labelNames []string, withDefaultLabels bool)
	//functions used for existing metrics
	SetEvmHandlerGaugeMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels)
	SetEvmHandlerGaugeMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels) 
	IncEvmHandlerCounterMetric(ctx context.Context, metricName string, defaultLabels *metric.FireflyDefaultLabels) 
	IncEvmHandlerCounterMetricWithLabels(ctx context.Context, metricName string, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels)
	ObserveEvmHandlerHistogramMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels)
	ObserveEvmHandlerHistogramMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels)
	ObserveEvmHandlerSummaryMetric(ctx context.Context, metricName string, number float64, defaultLabels *metric.FireflyDefaultLabels)
	ObserveEvmHandlerSummaryMetricWithLabels(ctx context.Context, metricName string, number float64, labels map[string]string, defaultLabels *metric.FireflyDefaultLabels)
}
