package metrics

import (
	"context"

	"github.com/hyperledger/firefly-transaction-manager/pkg/fftm"
)

type Manager struct {
	ctx            context.Context
	cancelCtx      func()
	metricsManager EvmMetrics
	fftm fftm.Manager
}

func NewEvmMetricsManager(ctx context.Context, fftm fftm.Manager) error {
	m := &Manager{
		ctx:            ctx,
		metricsManager: NewMetricsManager(ctx),
		fftm: fftm,
		
	}
	m.ctx, m.cancelCtx = context.WithCancel(ctx)
	return nil
}
