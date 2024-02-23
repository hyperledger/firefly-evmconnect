package metrics

import "github.com/prometheus/client_golang/prometheus"

var EvmTransactionSubmissionCounter prometheus.Counter

var (
	MetricsTransactionSubmission = "ff_transaction_submission_total"
)

func InitEvmCustomMetrics() {
	EvmTransactionSubmissionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: MetricsTransactionSubmission,
		Help: "Total number of transactions submitted to the EVM Connect",
	})
}

func RegsiterEvmCustomMetrics() {
	registry.MustRegister(EvmTransactionSubmissionCounter)
}
