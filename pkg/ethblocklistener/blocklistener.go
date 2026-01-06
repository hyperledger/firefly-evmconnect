// Copyright © 2026 Kaleido, Inc.
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

package ethblocklistener

import (
	"container/list"
	"context"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-common/pkg/retry"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-evmconnect/internal/retryutil"
	"github.com/hyperledger/firefly-evmconnect/pkg/etherrors"
	"github.com/hyperledger/firefly-evmconnect/pkg/ethrpc"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

type BlockListenerConfig struct {
	UnstableHeadLength      int           `json:"unstableHeadLength"`
	BlockPollingInterval    time.Duration `json:"blockPollingInterval"`
	HederaCompatibilityMode bool          `json:"hederaCompatibilityMode"`
	BlockCacheSize          int           `json:"blockCacheSize"`
}

type BlockListener interface {
	ReconcileConfirmationsForTransaction(ctx context.Context, txHash string, existingConfirmations []*ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationUpdateResult, *ethrpc.TxReceiptJSONRPC, error)
	ConfiguredUnstableHeadLength() int // provides a getter on the configuration for unstable head length - as this information is important to consumers (might be multiple from this block listener)
	AddConsumer(ctx context.Context, c *BlockUpdateConsumer)
	GetHighestBlock(ctx context.Context) (uint64, bool)
	GetBlockInfoByNumber(ctx context.Context, blockNumber uint64, allowCache bool, expectedParentHashStr string, expectedBlockHashStr string) (*ethrpc.BlockInfoJSONRPC, error)
	GetBlockInfoByHash(ctx context.Context, hash0xString string) (*ethrpc.BlockInfoJSONRPC, error)
	WaitClosed()
	UTSetBackend(rpcbackend.RPC)
}

type BlockUpdateConsumer struct {
	ID      *fftypes.UUID // could be an event stream ID for example - must be unique
	Ctx     context.Context
	Updates chan<- *ffcapi.BlockHashEvent
}

// blockListener has two functions:
// 1) To establish and keep track of what the head block height of the blockchain is, so event streams know how far from the head they are
// 2) To feed new block information to any registered consumers
type blockListener struct {
	ctx            context.Context
	retry          *retryutil.RetryWrapper
	backend        rpcbackend.RPC
	wsBackend      rpcbackend.WebSocketRPCClient // if configured the getting the blockheight will not complete until WS connects, overrides backend once connected
	listenLoopDone chan struct{}

	isStarted bool
	startDone chan struct{}

	initialBlockHeightObtained chan struct{}
	newHeadsTap                chan struct{}
	newHeadsSub                rpcbackend.Subscription
	highestBlockSet            bool
	highestBlock               uint64
	mux                        sync.RWMutex
	consumers                  map[fftypes.UUID]*BlockUpdateConsumer
	blockCache                 *lru.Cache
	BlockListenerConfig

	//  canonical chain
	canonicalChain *list.List
}

func NewBlockListener(ctx context.Context, retry *retry.Retry, conf *BlockListenerConfig, httpConf *ffresty.Config, wsConf *wsclient.WSConfig) (bl BlockListener, err error) {
	httpClient := ffresty.NewWithConfig(ctx, *httpConf)
	var wsBackend rpcbackend.WebSocketRPCClient
	if wsConf != nil {
		wsBackend = rpcbackend.NewWSRPCClient(wsConf)
	}
	return NewBlockListenerSupplyBackend(ctx, retry, conf, rpcbackend.NewRPCClient(httpClient), wsBackend)
}

func NewBlockListenerSupplyBackend(ctx context.Context, retry *retry.Retry, conf *BlockListenerConfig, httpBackend rpcbackend.RPC, wsBackend rpcbackend.WebSocketRPCClient) (_ BlockListener, err error) {
	bl := &blockListener{
		ctx:                        log.WithLogField(ctx, "role", "blocklistener"),
		retry:                      &retryutil.RetryWrapper{Retry: retry},
		backend:                    httpBackend, // use the HTTP backend - might get overwritten by a connected websocket later
		wsBackend:                  wsBackend,
		isStarted:                  false,
		startDone:                  make(chan struct{}),
		initialBlockHeightObtained: make(chan struct{}),
		newHeadsTap:                make(chan struct{}),
		highestBlockSet:            false,
		highestBlock:               0,
		consumers:                  make(map[fftypes.UUID]*BlockUpdateConsumer),
		canonicalChain:             list.New(),
		BlockListenerConfig:        *conf,
	}
	bl.blockCache, err = lru.New(conf.BlockCacheSize)
	if err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgCacheInitFail, "block")
	}
	return bl, nil
}

func (bl *blockListener) UTSetBackend(backend rpcbackend.RPC) {
	bl.backend = backend
}

func (bl *blockListener) ConfiguredUnstableHeadLength() int {
	return bl.BlockListenerConfig.UnstableHeadLength
}

// setting block filter status updates that new block filter has been created
func (bl *blockListener) markStarted() {
	if !bl.isStarted {
		bl.isStarted = true
		close(bl.startDone)
	}
}

func (bl *blockListener) waitUntilStarted(ctx context.Context) {
	select {
	case <-bl.startDone:
	case <-bl.ctx.Done():
	case <-ctx.Done():
	}
}

func (bl *blockListener) newHeadsSubListener() {
	for range bl.newHeadsSub.Notifications() {
		select {
		case bl.newHeadsTap <- struct{}{}:
			// Do nothing apart from tap the listener to wake up early
			// when there's a notification to the change of the head.
		default:
		}
	}
}

// getBlockHeightWithRetry keeps retrying attempting to get the initial block height until successful
func (bl *blockListener) establishBlockHeightWithRetry() error {
	wsConnected := false
	return bl.retry.Do(bl.ctx, "get initial block height", func(_ int) (retry bool, err error) {
		// If we have a WebSocket backend, then we connect it and switch over to using it
		// (we accept an un-locked update here to backend, as the most important routine that's
		// querying block state is the one we're called on)
		if bl.wsBackend != nil {
			if !wsConnected {
				if err := bl.wsBackend.Connect(bl.ctx); err != nil {
					log.L(bl.ctx).Warnf("WebSocket connection failed, blocking startup of block listener: %s", err)
					return true, err
				}
				bl.backend = bl.wsBackend
				// if we retry subscribe, we don't want to retry connect
				wsConnected = true
			}
			if bl.newHeadsSub == nil {
				// Once subscribed the backend will keep us subscribed over reconnect
				sub, rpcErr := bl.wsBackend.Subscribe(bl.ctx, "newHeads")
				if rpcErr != nil {
					return true, rpcErr.Error()
				}
				bl.newHeadsSub = sub
				go bl.newHeadsSubListener()
			}
			// Ok all JSON/RPC from this point on uses our WS Backend, thus ensuring we're
			// sticky to the same node that the WS is connected to when we're doing queries
			// and building our cache.
			bl.backend = bl.wsBackend
		}

		// Now get the block height
		var hexBlockHeight ethtypes.HexInteger
		rpcErr := bl.backend.CallRPC(bl.ctx, &hexBlockHeight, "eth_blockNumber")
		if rpcErr != nil {
			log.L(bl.ctx).Warnf("Block height could not be obtained: %s", rpcErr.Message)
			return true, rpcErr.Error()
		}

		bl.setHighestBlock(hexBlockHeight.BigInt().Uint64())
		return false, nil
	})
}

func (bl *blockListener) waitNextIteration() bool {
	select {
	case <-bl.ctx.Done():
		return false
	case <-time.After(bl.BlockPollingInterval):
	case <-bl.newHeadsTap:
	}
	return true
}

func (bl *blockListener) listenLoop() {
	defer close(bl.listenLoopDone)

	err := bl.establishBlockHeightWithRetry()
	close(bl.initialBlockHeightObtained)
	if err != nil {
		log.L(bl.ctx).Warnf("Block listener exiting before establishing initial block height: %s", err)
	}

	var filter string
	failCount := 0
	gapPotential := true
	firstIteration := true
	for {
		if failCount > 0 {
			if bl.retry.DoFailureDelay(bl.ctx, failCount) {
				log.L(bl.ctx).Debugf("Block listener loop exiting")
				return
			}
		} else {
			// Sleep for the polling interval, or until we're shoulder tapped by the newHeads listener
			if !firstIteration {
				if !bl.waitNextIteration() {
					log.L(bl.ctx).Debugf("Block listener loop stopping")
					return
				}
			} else {
				firstIteration = false
			}
		}

		if filter == "" {
			err := bl.backend.CallRPC(bl.ctx, &filter, "eth_newBlockFilter")
			if err != nil {
				log.L(bl.ctx).Errorf("Failed to establish new block filter: %s", err.Message)
				failCount++
				continue
			}
			bl.markStarted()
		}

		var blockHashes []ethtypes.HexBytes0xPrefix
		rpcErr := bl.backend.CallRPC(bl.ctx, &blockHashes, "eth_getFilterChanges", filter)
		if rpcErr != nil {
			if etherrors.MapError(etherrors.FilterRPCMethods, rpcErr.Error()) == ffcapi.ErrorReasonNotFound {
				log.L(bl.ctx).Warnf("Block filter '%v' no longer valid. Recreating filter: %s", filter, rpcErr.Message)
				filter = ""
				gapPotential = true
			}
			log.L(bl.ctx).Errorf("Failed to query block filter changes: %s", rpcErr.Message)
			failCount++
			continue
		}
		log.L(bl.ctx).Debugf("Block filter received new block hashes: %+v", blockHashes)

		update := &ffcapi.BlockHashEvent{GapPotential: gapPotential, Created: fftypes.Now()}
		var notifyPos *list.Element
		for _, h := range blockHashes {
			if len(h) != 32 {
				if !bl.HederaCompatibilityMode {
					log.L(bl.ctx).Errorf("Attempted to index block header with non-standard length: %d", len(h))
					failCount++
					continue
				}

				if len(h) < 32 {
					log.L(bl.ctx).Errorf("Cannot index block header hash of length: %d", len(h))
					failCount++
					continue
				}

				h = h[0:32]
			}

			// Do a lookup of the block (which will then go into our cache).
			bi, err := bl.GetBlockInfoByHash(bl.ctx, h.String())
			switch {
			case err != nil:
				log.L(bl.ctx).Debugf("Failed to query block '%s': %s", h, err)
			case bi == nil:
				log.L(bl.ctx).Debugf("Block '%s' no longer available after notification (assuming due to re-org)", h)
			default:
				candidate := bl.reconcileCanonicalChain(bi)
				// Check this is the lowest position to notify from
				if candidate != nil && (notifyPos == nil || candidate.Value.(*ffcapi.MinimalBlockInfo).BlockNumber <= notifyPos.Value.(*ffcapi.MinimalBlockInfo).BlockNumber) {
					notifyPos = candidate
				}
			}
		}
		if notifyPos != nil {
			// We notify for all hashes from the point of change in the chain onwards
			for notifyPos != nil {
				update.BlockHashes = append(update.BlockHashes, notifyPos.Value.(*ffcapi.MinimalBlockInfo).BlockHash)
				notifyPos = notifyPos.Next()
			}

			// Take a copy of the consumers in the lock
			bl.mux.Lock()
			consumers := make([]*BlockUpdateConsumer, 0, len(bl.consumers))
			for _, c := range bl.consumers {
				consumers = append(consumers, c)
			}
			bl.mux.Unlock()

			// Spin through delivering the block update
			bl.dispatchToConsumers(consumers, update)
		}

		// Reset retry count when we have a full successful loop
		failCount = 0
		gapPotential = false

	}
}

// reconcileCanonicalChain takes an update on a block, and reconciles it against the in-memory view of the
// head of the canonical chain we have. If these blocks do not just fit onto the end of the chain, then we
// work backwards building a new view and notify about all blocks that are changed in that process.
func (bl *blockListener) reconcileCanonicalChain(bi *ethrpc.BlockInfoJSONRPC) *list.Element {
	mbi := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(bi.Number.BigInt().Uint64()),
		BlockHash:   bi.Hash.String(),
		ParentHash:  bi.ParentHash.String(),
	}
	bl.checkAndSetHighestBlock(mbi.BlockNumber.Uint64())

	// Find the position of this block in the block sequence
	pos := bl.canonicalChain.Back()
	for {
		if pos == nil || pos.Value == nil {
			// We've eliminated all the existing chain (if there was any)
			return bl.handleNewBlock(mbi, nil)
		}
		posBlock := pos.Value.(*ffcapi.MinimalBlockInfo)
		switch {
		case posBlock.Equal(mbi):
			// This is a duplicate - no need to notify of anything
			return nil
		case posBlock.BlockNumber.Uint64() == mbi.BlockNumber.Uint64():
			// We are replacing a block in the chain
			return bl.handleNewBlock(mbi, pos.Prev())
		case posBlock.BlockNumber.Uint64() < mbi.BlockNumber.Uint64():
			// We have a position where this block goes
			return bl.handleNewBlock(mbi, pos)
		default:
			// We've not wound back to the point this block fits yet
			pos = pos.Prev()
		}
	}
}

// handleNewBlock rebuilds the canonical chain around a new block, checking if we need to rebuild our
// view of the canonical chain behind it, or trimming anything after it that is invalidated by a new fork.
func (bl *blockListener) handleNewBlock(mbi *ffcapi.MinimalBlockInfo, addAfter *list.Element) *list.Element {
	// If we have an existing canonical chain before this point, then we need to check we've not
	// invalidated that with this block. If we have, then we have to re-verify our whole canonical
	// chain from the first block. Then notify from the earliest point where it has diverged.
	if addAfter != nil {
		prevBlock := addAfter.Value.(*ffcapi.MinimalBlockInfo)
		if prevBlock.BlockNumber.Uint64() != (mbi.BlockNumber.Uint64()-1) || prevBlock.BlockHash != mbi.ParentHash {
			log.L(bl.ctx).Infof("Notified of block %d / %s that does not fit after block %d / %s (expected parent: %s)", mbi.BlockNumber.Uint64(), mbi.BlockHash, prevBlock.BlockNumber.Uint64(), prevBlock.BlockHash, mbi.ParentHash)
			return bl.rebuildCanonicalChain()
		}
	}

	// Ok, we can add this block
	var newElem *list.Element
	if addAfter == nil {
		_ = bl.canonicalChain.Init()
		newElem = bl.canonicalChain.PushBack(mbi)
	} else {
		newElem = bl.canonicalChain.InsertAfter(mbi, addAfter)
		// Trim everything from this point onwards. Note that the following cases are covered on other paths:
		// - This was just a duplicate notification of a block that fits into our chain - discarded in reconcileCanonicalChain()
		// - There was a gap before us in the chain, and the tail is still valid - we would have called rebuildCanonicalChain() above
		nextElem := newElem.Next()
		for nextElem != nil {
			toRemove := nextElem
			nextElem = nextElem.Next()
			_ = bl.canonicalChain.Remove(toRemove)
		}
	}

	// Trim the amount of history we keep based on the configured amount of instability at the front of the chain
	for bl.canonicalChain.Len() > bl.UnstableHeadLength {
		_ = bl.canonicalChain.Remove(bl.canonicalChain.Front())
	}

	log.L(bl.ctx).Debugf("Added block %d / %s parent=%s to in-memory canonical chain (new length=%d)", mbi.BlockNumber.Uint64(), mbi.BlockHash, mbi.ParentHash, bl.canonicalChain.Len())

	return newElem
}

// rebuildCanonicalChain is called (only on non-empty case) when our current chain does not seem to line up with
// a recent block advertisement. So we need to work backwards to the last point of consistency with the current
// chain and re-query the chain state from there.
func (bl *blockListener) rebuildCanonicalChain() *list.Element {
	// If none of our blocks were valid, start from the first block number we've notified about previously
	lastValidBlock := bl.trimToLastValidBlock()
	var nextBlockNumber uint64
	var expectedParentHash string
	if lastValidBlock != nil {
		nextBlockNumber = lastValidBlock.BlockNumber.Uint64() + 1
		log.L(bl.ctx).Infof("Canonical chain partially rebuilding from block %d", nextBlockNumber)
		expectedParentHash = lastValidBlock.BlockHash
	} else {
		firstBlock := bl.canonicalChain.Front()
		if firstBlock == nil || firstBlock.Value == nil {
			return nil
		}
		nextBlockNumber = firstBlock.Value.(*ffcapi.MinimalBlockInfo).BlockNumber.Uint64()
		log.L(bl.ctx).Warnf("Canonical chain re-initialized at block %d", nextBlockNumber)
		// Clear out the whole chain
		bl.canonicalChain = bl.canonicalChain.Init()
	}
	var notifyPos *list.Element
	for {
		var bi *ethrpc.BlockInfoJSONRPC
		var reason ffcapi.ErrorReason
		err := bl.retry.Do(bl.ctx, "rebuild listener canonical chain", func(_ int) (retry bool, err error) {
			bi, err = bl.GetBlockInfoByNumber(bl.ctx, nextBlockNumber, false, "", "")
			return true, err
		})
		if err != nil {
			if reason != ffcapi.ErrorReasonNotFound {
				return nil // Context must have been cancelled
			}
		}
		if bi == nil {
			log.L(bl.ctx).Infof("Canonical chain rebuilt the chain to the head block %d", nextBlockNumber-1)
			break
		}
		mbi := &ffcapi.MinimalBlockInfo{
			BlockNumber: fftypes.FFuint64(bi.Number.BigInt().Uint64()),
			BlockHash:   bi.Hash.String(),
			ParentHash:  bi.ParentHash.String(),
		}

		// It's possible the chain will change while we're doing this, and we fall back to the next block notification
		// to sort that out.
		if expectedParentHash != "" && mbi.ParentHash != expectedParentHash {
			log.L(bl.ctx).Infof("Canonical chain rebuilding stopped at block: %d due to mismatch hash for parent block (%d): %s (expected: %s)", nextBlockNumber, nextBlockNumber-1, mbi.ParentHash, expectedParentHash)
			break
		}
		expectedParentHash = mbi.BlockHash
		nextBlockNumber++

		// Note we do not trim to a length here, as we need to notify for every block we haven't notified for.
		// Trimming to a length will happen when we get blocks that slot into our existing view
		newElem := bl.canonicalChain.PushBack(mbi)
		if notifyPos == nil {
			notifyPos = newElem
		}

		bl.checkAndSetHighestBlock(mbi.BlockNumber.Uint64())

	}
	return notifyPos
}

func (bl *blockListener) trimToLastValidBlock() (lastValidBlock *ffcapi.MinimalBlockInfo) {
	// First remove from the end until we get a block that matches the current un-cached query view from the chain
	lastElem := bl.canonicalChain.Back()
	var startingNumber *uint64
	for lastElem != nil && lastElem.Value != nil {

		// Query the block that is no at this blockNumber
		currentViewBlock := lastElem.Value.(*ffcapi.MinimalBlockInfo)
		if startingNumber == nil {
			currentNumber := currentViewBlock.BlockNumber.Uint64()
			startingNumber = &currentNumber
			log.L(bl.ctx).Debugf("Canonical chain checking from last block: %d", startingNumber)
		}
		var freshBlockInfo *ethrpc.BlockInfoJSONRPC
		err := bl.retry.Do(bl.ctx, "rebuild listener canonical chain", func(_ int) (retry bool, err error) {
			log.L(bl.ctx).Debugf("Canonical chain validating block: %d", currentViewBlock.BlockNumber.Uint64())
			freshBlockInfo, err = bl.GetBlockInfoByNumber(bl.ctx, currentViewBlock.BlockNumber.Uint64(), false, "", "")
			return true, err
		})
		if err != nil {
			return nil // Context must have been cancelled
		}

		if freshBlockInfo != nil && freshBlockInfo.Hash.String() == currentViewBlock.BlockHash {
			log.L(bl.ctx).Debugf("Canonical chain found last valid block %d", currentViewBlock.BlockNumber.Uint64())
			lastValidBlock = currentViewBlock
			// Trim everything after this point, as it's invalidated
			nextElem := lastElem.Next()
			for nextElem != nil {
				toRemove := lastElem
				nextElem = nextElem.Next()
				_ = bl.canonicalChain.Remove(toRemove)
			}
			break
		}
		lastElem = lastElem.Prev()
	}

	if startingNumber != nil && lastValidBlock != nil && *startingNumber != lastValidBlock.BlockNumber.Uint64() {
		log.L(bl.ctx).Debugf("Canonical chain trimmed from block %d to block %d (total number of in memory blocks: %d)", startingNumber, lastValidBlock.BlockNumber.Uint64(), bl.UnstableHeadLength)
	}
	return lastValidBlock
}

func (bl *blockListener) dispatchToConsumers(consumers []*BlockUpdateConsumer, update *ffcapi.BlockHashEvent) {
	for _, c := range consumers {
		log.L(bl.ctx).Tracef("Notifying consumer %s of blocks %v (gap=%t)", c.ID, update.BlockHashes, update.GapPotential)
		select {
		case c.Updates <- update:
		case <-bl.ctx.Done(): // loop, we're stopping and will exit on next loop
		case <-c.Ctx.Done():
			log.L(bl.ctx).Debugf("Block update consumer %s closed", c.ID)
			bl.mux.Lock()
			delete(bl.consumers, *c.ID)
			bl.mux.Unlock()
		}
	}
}

func (bl *blockListener) checkAndStartListenerLoop() {
	bl.mux.Lock()
	defer bl.mux.Unlock()
	if bl.listenLoopDone == nil {
		bl.listenLoopDone = make(chan struct{})
		go bl.listenLoop()
	}
}

func (bl *blockListener) AddConsumer(ctx context.Context, c *BlockUpdateConsumer) {
	bl.checkAndStartListenerLoop()
	bl.waitUntilStarted(ctx) // need to make sure the listener is started before adding any consumers
	bl.mux.Lock()
	defer bl.mux.Unlock()
	bl.consumers[*c.ID] = c
}

func (bl *blockListener) GetHighestBlock(ctx context.Context) (uint64, bool) {
	bl.checkAndStartListenerLoop()
	// block height will be established as the first step of listener startup process
	// so we don't need to wait for the entire startup process to finish to return the result
	bl.mux.Lock()
	highestBlockSet := bl.highestBlockSet
	bl.mux.Unlock()
	// if not yet initialized, wait to be initialized
	if !highestBlockSet {
		select {
		case <-bl.initialBlockHeightObtained:
		case <-ctx.Done():
			// Inform caller we timed out, or were closed
			return 0, false
		}
	}
	bl.mux.Lock()
	highestBlock := bl.highestBlock
	bl.mux.Unlock()
	log.L(ctx).Debugf("ChainHead=%d", highestBlock)
	return highestBlock, true
}

func (bl *blockListener) setHighestBlock(block uint64) {
	bl.mux.Lock()
	defer bl.mux.Unlock()
	bl.highestBlock = block
	bl.highestBlockSet = true
}

func (bl *blockListener) checkAndSetHighestBlock(block uint64) {
	bl.mux.Lock()
	defer bl.mux.Unlock()
	if block > bl.highestBlock {
		bl.highestBlock = block
		bl.highestBlockSet = true
	}
}

func (bl *blockListener) WaitClosed() {
	bl.mux.Lock()
	listenLoopDone := bl.listenLoopDone
	bl.mux.Unlock()
	if bl.wsBackend != nil {
		_ = bl.wsBackend.UnsubscribeAll(bl.ctx)
		bl.wsBackend.Close()
	}
	if listenLoopDone != nil {
		select {
		case <-listenLoopDone:
		case <-bl.ctx.Done():
		}
	}
}
