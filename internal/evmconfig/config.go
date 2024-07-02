package evmconfig

import "github.com/hyperledger/firefly-common/pkg/config"

var ffc = config.AddRootKey

var CorsConfig config.Section

var MetricsConfig config.Section

var (
	MetricsEnabled = ffc("metrics.enabled")
	MetricsPath    = ffc("metrics.path")
)
