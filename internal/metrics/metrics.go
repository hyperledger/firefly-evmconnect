package metrics

import (
	"context"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-evmconnect/internal/evmconfig"
)

type Manager interface {
	IsMetricsEnabled() bool
}

type metricsManager struct {
	ctx            context.Context
	metricsEnabled bool
	timeMap        map[string]time.Time
}

func NewMetricsManaer(ctx context.Context) Manager {
	return &metricsManager{
		ctx:            ctx,
		metricsEnabled: config.GetBool(evmconfig.MetricsEnabled),
		timeMap:        make(map[string]time.Time),
	}
}

func (mm *metricsManager) IsMetricsEnabled() bool {
	return mm.metricsEnabled
}
