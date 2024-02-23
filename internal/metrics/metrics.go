package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-evmconnect/internal/evmconfig"
)

var mutex = &sync.Mutex{}

type Manager interface {
	IsMetricsEnabled() bool
	GetTime(id string) time.Time
	AddTime(id string)
}

type metricsManager struct {
	ctx            context.Context
	metricsEnabled bool
	timeMap        map[string]time.Time
}

func NewMetricsManager(ctx context.Context) Manager {
	return &metricsManager{
		ctx:            ctx,
		metricsEnabled: config.GetBool(evmconfig.MetricsEnabled),
		timeMap:        make(map[string]time.Time),
	}
}

func (mm *metricsManager) IsMetricsEnabled() bool {
	return mm.metricsEnabled
}

func (mm *metricsManager) AddTime(id string) {
	mutex.Lock()
	mm.timeMap[id] = time.Now()
	mutex.Unlock()
}

func (mm *metricsManager) GetTime(id string) time.Time {
	mutex.Lock()
	time := mm.timeMap[id]
	mutex.Unlock()
	return time
}