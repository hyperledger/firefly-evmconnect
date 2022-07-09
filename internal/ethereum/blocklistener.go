// Copyright © 2022 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ethereum

import (
	"context"
	"sync"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

type blockUpdateConsumer struct {
	id      *fftypes.UUID // could be an event stream ID for example - must be unique
	ctx     context.Context
	updates chan<- *ffcapi.BlockHashEvent
}

// blockListener has two function:
// 1) To establish and keep track of what the head block height of the blockchain is, so event streams know how far from the head they are
// 2) To feed new block information to any registered consumers
type blockListener struct {
	ctx                        context.Context
	c                          *ethConnector
	listenLoopDone             chan struct{}
	initialBlockHeightObtained chan struct{}
	highestBlock               int64
	mux                        sync.Mutex
	consumers                  map[fftypes.UUID]*blockUpdateConsumer
	blockPollingInterval       time.Duration
}

func newBlockListener(ctx context.Context, c *ethConnector, conf config.Section) *blockListener {
	bl := &blockListener{
		ctx:                        log.WithLogField(ctx, "role", "blocklistener"),
		c:                          c,
		initialBlockHeightObtained: make(chan struct{}),
		highestBlock:               -1,
		consumers:                  make(map[fftypes.UUID]*blockUpdateConsumer),
		blockPollingInterval:       conf.GetDuration(BlockPollingInterval),
	}
	return bl
}

// getBlockHeightWithRetry keeps retrying attempting to get the initial block height until successful
func (bl *blockListener) establishBlockHeightWithRetry() error {
	return bl.c.retry.Do(bl.ctx, "get initial block height", func(attempt int) (retry bool, err error) {
		var hexBlockHeight ethtypes.HexInteger
		err = bl.c.backend.Invoke(bl.ctx, &hexBlockHeight, "eth_blockNumber")
		if err != nil {
			log.L(bl.ctx).Warnf("Block height could not be obtained: %s", err)
			return true, err
		}
		bl.mux.Lock()
		bl.highestBlock = hexBlockHeight.BigInt().Int64()
		bl.mux.Unlock()
		return false, nil
	})
}

func (bl *blockListener) listenLoop() {
	defer close(bl.listenLoopDone)

	err := bl.establishBlockHeightWithRetry()
	close(bl.initialBlockHeightObtained)
	if err != nil {
		log.L(bl.ctx).Warnf("Block listener exiting before establishing initial block height: %s", err)
	}

	var filter *ethtypes.HexInteger
	retryCount := 0
	gapPotential := true
	for {
		// Sleep for the polling interval
		select {
		case <-time.After(bl.blockPollingInterval):
		case <-bl.ctx.Done():
			log.L(bl.ctx).Debugf("Block listener loop stopping")
			return
		}

		if filter == nil {
			err := bl.c.backend.Invoke(bl.ctx, &filter, "eth_newBlockFilter")
			if err != nil {
				bl.c.doDelay(bl.ctx, &retryCount, err)
				continue
			}
		}

		var blockHashes []ethtypes.HexBytes0xPrefix
		err := bl.c.backend.Invoke(bl.ctx, &blockHashes, "eth_getFilterChanges", filter)
		if err != nil {
			if mapError(filterRPCMethods, err) == ffcapi.ErrorReasonNotFound {
				log.L(bl.ctx).Warnf("Block filter '%s' no longer valid. Recreating filter: %s", filter, err)
				filter = nil
				gapPotential = true
			}
			continue
		}

		update := &ffcapi.BlockHashEvent{GapPotential: gapPotential}
		update.BlockHashes = make([]string, 0, len(blockHashes))
		for _, h := range blockHashes {
			// Do a lookup of the block (which will then go into our cache). This lets us keep the high block watermark updated
			update.BlockHashes = append(update.BlockHashes, h.String())
			bi, err := bl.c.getBlockInfoByHash(bl.ctx, h.String())
			switch {
			case err != nil:
				log.L(bl.ctx).Debugf("Failed to query block '%s': %s", h, err)
			case bi == nil:
				log.L(bl.ctx).Debugf("Block '%s' no longer available after notification (assuming due to re-org)", h)
			default:
				blockHeight := bi.Number.BigInt().Int64()
				bl.mux.Lock()
				if blockHeight > bl.highestBlock {
					bl.highestBlock = blockHeight
				}
				bl.mux.Unlock()
			}
		}

		// Take a copy of the consumers in the lock
		bl.mux.Lock()
		consumers := make([]*blockUpdateConsumer, 0, len(bl.consumers))
		for _, c := range bl.consumers {
			consumers = append(consumers, c)
		}
		bl.mux.Unlock()

		// Spin through delivering the block update
		for _, c := range consumers {
			select {
			case c.updates <- update:
			case <-bl.ctx.Done(): // loop, we're stopping and will exit on next loop
			case <-c.ctx.Done():
				log.L(bl.ctx).Debugf("Block update consumer %s closed", c.id)
				bl.mux.Lock()
				delete(bl.consumers, *c.id)
				bl.mux.Unlock()
			}
		}

		// Reset retry count when we have a full successful loop
		retryCount = 0
		gapPotential = false
	}
}

func (bl *blockListener) checkStartedLocked() {
	if bl.listenLoopDone == nil {
		bl.listenLoopDone = make(chan struct{})
		go bl.listenLoop()
	}
}

func (bl *blockListener) addConsumer(c *blockUpdateConsumer) {
	bl.mux.Lock()
	defer bl.mux.Unlock()
	bl.checkStartedLocked()
	bl.consumers[*c.id] = c
}

func (bl *blockListener) getHighestBlock() int64 {
	bl.mux.Lock()
	bl.checkStartedLocked()
	highestBlock := bl.highestBlock
	bl.mux.Unlock()
	// if not yet initialized, wait to be initialized
	if highestBlock < 0 {
		select {
		case <-bl.initialBlockHeightObtained:
		case <-bl.ctx.Done():
		}
	}
	bl.mux.Lock()
	highestBlock = bl.highestBlock
	bl.mux.Unlock()
	return highestBlock
}
