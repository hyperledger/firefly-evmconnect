package evmconfig

import "github.com/hyperledger/firefly-common/pkg/config"

var ffc = config.AddRootKey

var (
	MetricsEnabled = ffc("metrics.enabled")
)
