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
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/pkg/etherrors"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// trustedListenLoop is the listen loop for BlockListenerModeTrusted.
//
// It uses the same block filter (eth_newBlockFilter / eth_getFilterChanges) and
// optional WS newHeads subscription as the canonical listener for wake-up
// signals, but does NOT resolve block hashes to headers. Instead it calls only
// eth_blockNumber to track chain height and dispatches the raw block hashes to
// consumers.
//
// RPC footprint: eth_blockNumber, eth_newBlockFilter, eth_getFilterChanges,
// optional eth_subscribe("newHeads"). Zero eth_getBlockByHash / eth_getBlockByNumber.
func (bl *blockListener) trustedListenLoop() {
	defer close(bl.listenLoopDone)

	err := bl.establishBlockHeightWithRetry()
	close(bl.initialBlockHeightObtained)
	if err != nil {
		log.L(bl.ctx).Warnf("Block listener exiting before establishing initial block height: %s", err)
		return
	}

	var filter string
	failCount := 0
	gapPotential := true
	firstIteration := true
	for {
		if failCount > 0 {
			if bl.retry.DoFailureDelay(bl.ctx, failCount) {
				log.L(bl.ctx).Debugf("Trusted block listener loop exiting")
				return
			}
		} else if !firstIteration {
			if !bl.waitNextIteration() {
				log.L(bl.ctx).Debugf("Trusted block listener loop stopping")
				return
			}
		} else {
			firstIteration = false
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

		// Query the chain head — this is the only way we track height in trusted mode.
		var hexBlockHeight ethtypes.HexInteger
		rpcErr = bl.backend.CallRPC(bl.ctx, &hexBlockHeight, "eth_blockNumber")
		if rpcErr != nil {
			log.L(bl.ctx).Errorf("Failed to query block height: %s", rpcErr.Message)
			failCount++
			continue
		}
		bl.setHighestBlock(hexBlockHeight.BigInt().Uint64())

		if len(blockHashes) > 0 {
			update := &ffcapi.BlockHashEvent{GapPotential: gapPotential, Created: fftypes.Now()}
			for _, h := range blockHashes {
				update.BlockHashes = append(update.BlockHashes, h.String())
			}

			bl.consumerMux.Lock()
			consumers := make([]*BlockUpdateConsumer, 0, len(bl.consumers))
			for _, c := range bl.consumers {
				consumers = append(consumers, c)
			}
			bl.consumerMux.Unlock()

			bl.dispatchToConsumers(consumers, update)
		}

		failCount = 0
		gapPotential = false
	}
}
