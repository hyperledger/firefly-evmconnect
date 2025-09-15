// Copyright © 2025 Kaleido, Inc.
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
	"container/list"
	"context"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (bl *blockListener) reconcileConfirmationsForTransaction(ctx context.Context, txHash string, confirmMap *ffcapi.ConfirmationMap, targetConfirmationCount uint64) (*ffcapi.ConfirmationMapUpdateResult, error) {
	// Initialize the output context
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap:         confirmMap,
		HasNewFork:              false,
		Rebuilt:                 false,
		HasNewConfirmation:      false,
		Confirmed:               false,
		TargetConfirmationCount: targetConfirmationCount,
	}

	txBlockInfo, err := bl.getBlockInfoContainsTxHash(ctx, txHash)
	if err != nil {
		log.L(ctx).Errorf("Failed to fetch block info using tx hash %s: %v", txHash, err)
		return nil, err
	}

	if txBlockInfo == nil {
		log.L(ctx).Debugf("Transaction %s not found in any block", txHash)
		return occ, nil
	}

	// Compare the existing confirmation queue with the in-memory linked list
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	return occ, nil
}

// NOTE: this function only build up the confirmation queue uses the in-memory canonical chain
// it does not build up the canonical chain
// compareAndUpdateConfirmationQueue compares the existing confirmation queue with the in-memory linked list
// this function obtains the read lock on the canonical chain, so it should not make any long-running queries

func (bl *blockListener) compareAndUpdateConfirmationQueue(ctx context.Context, occ *ffcapi.ConfirmationMapUpdateResult, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) {
	bl.mux.RLock()
	defer bl.mux.RUnlock()
	txBlockNumber := txBlockInfo.BlockNumber.Uint64()
	txBlockHash := txBlockInfo.BlockHash

	chainHead := bl.canonicalChain.Front().Value.(*ffcapi.MinimalBlockInfo)
	chainTail := bl.canonicalChain.Back().Value.(*ffcapi.MinimalBlockInfo)
	if chainHead == nil || chainTail == nil || chainTail.BlockNumber.Uint64() < txBlockNumber {
		log.L(ctx).Debugf("Canonical chain is waiting for the transaction block %d to be indexed", txBlockNumber)
		return
	}

	// Initialize confirmation map and get existing queue
	existingQueue := bl.initializeConfirmationMap(occ, txBlockInfo)

	// Validate and process existing confirmations
	newQueue, currentBlock := bl.processExistingConfirmations(ctx, occ, txBlockInfo, existingQueue, chainHead, targetConfirmationCount)

	if currentBlock == nil {
		// the tx block is not in the canonical chain
		// we should just return the existing block confirmations and wait for future call to correct it
		return
	}

	// Build new confirmations from canonical chain only if not already confirmed
	if !occ.Confirmed {
		newQueue = bl.buildNewConfirmations(occ, newQueue, currentBlock, txBlockNumber, targetConfirmationCount)
	}
	occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash] = newQueue

	if occ.CanonicalBlockHash != txBlockHash {
		occ.CanonicalBlockHash = txBlockHash
	}
}

func (bl *blockListener) initializeConfirmationMap(occ *ffcapi.ConfirmationMapUpdateResult, txBlockInfo *ffcapi.MinimalBlockInfo) []*ffcapi.MinimalBlockInfo {
	txBlockHash := txBlockInfo.BlockHash

	if occ.ConfirmationMap == nil || len(occ.ConfirmationMap.ConfirmationQueueMap) == 0 {
		occ.ConfirmationMap = &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				txBlockHash: {txBlockInfo},
			},
			CanonicalBlockHash: txBlockHash,
		}
		return nil
	}

	existingQueue := occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash]
	if len(existingQueue) > 0 {
		existingTxBlock := existingQueue[0]
		if !existingTxBlock.Equal(txBlockInfo) {
			// the tx block in the existing queue does not match the new tx block we queried from the chain
			// rebuild a new confirmation queue with the new tx block
			occ.HasNewFork = true
			occ.Rebuilt = true
			occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash] = []*ffcapi.MinimalBlockInfo{txBlockInfo}
			return nil
		}
	}

	return existingQueue
}

func (bl *blockListener) processExistingConfirmations(ctx context.Context, occ *ffcapi.ConfirmationMapUpdateResult, txBlockInfo *ffcapi.MinimalBlockInfo, existingQueue []*ffcapi.MinimalBlockInfo, chainHead *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) ([]*ffcapi.MinimalBlockInfo, *list.Element) {
	txBlockNumber := txBlockInfo.BlockNumber.Uint64()

	newQueue := []*ffcapi.MinimalBlockInfo{txBlockInfo}

	currentBlock := bl.canonicalChain.Front()
	// iterate to the tx block if the chain head is earlier than the tx block
	for currentBlock != nil && currentBlock.Value.(*ffcapi.MinimalBlockInfo).BlockNumber.Uint64() <= txBlockNumber {
		if currentBlock.Value.(*ffcapi.MinimalBlockInfo).BlockNumber.Uint64() == txBlockNumber {
			// the tx block is already in the canonical chain
			// we need to check if the tx block is the same as the chain head
			if !currentBlock.Value.(*ffcapi.MinimalBlockInfo).Equal(txBlockInfo) {
				// the tx block information is different from the same block number in the canonical chain
				// the tx confirmation block is not on the same fork as the canonical chain
				// we should just return the existing block confirmations and wait for future call to correct it
				return newQueue, nil
			}
		}
		currentBlock = currentBlock.Next()
	}

	if len(existingQueue) <= 1 {
		return newQueue, currentBlock
	}

	existingConfirmations := existingQueue[1:]
	return bl.validateExistingConfirmations(
		ctx, occ, newQueue, existingConfirmations, currentBlock, chainHead, txBlockInfo, targetConfirmationCount,
	)
}

func (bl *blockListener) validateExistingConfirmations(ctx context.Context, occ *ffcapi.ConfirmationMapUpdateResult, newQueue []*ffcapi.MinimalBlockInfo, existingConfirmations []*ffcapi.MinimalBlockInfo, currentBlock *list.Element, chainHead *ffcapi.MinimalBlockInfo, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) ([]*ffcapi.MinimalBlockInfo, *list.Element) {
	txBlockNumber := txBlockInfo.BlockNumber.Uint64()
	lastExistingConfirmation := existingConfirmations[len(existingConfirmations)-1]
	if lastExistingConfirmation.BlockNumber.Uint64() < chainHead.BlockNumber.Uint64() &&
		// ^^ the highest block number in the existing confirmations is lower than the highest block number in the canonical chain
		(lastExistingConfirmation.BlockNumber.Uint64() != chainHead.BlockNumber.Uint64()-1 ||
			lastExistingConfirmation.BlockHash != chainHead.ParentHash) {
		// ^^ and the last existing confirmation is not the parent of the canonical chain head
		// Therefore, there is no connection between the existing confirmations and the canonical chain
		// so that we cannot validate the existing confirmations are from the same fork as the canonical chain
		// so we need to rebuild the confirmations queue
		occ.Rebuilt = true
		return newQueue, currentBlock
	}

	var previousExistingConfirmation *ffcapi.MinimalBlockInfo
	queueIndex := 0

	connectionBlockNumber := currentBlock.Value.(*ffcapi.MinimalBlockInfo).BlockNumber.Uint64()

	for currentBlock != nil && queueIndex < len(existingConfirmations) {
		existingConfirmation := existingConfirmations[queueIndex]
		if existingConfirmation.BlockNumber.Uint64() <= txBlockNumber {
			log.L(ctx).Debugf("Existing confirmation queue is corrupted, the first block is earlier than the tx block: %d", existingConfirmation.BlockNumber.Uint64())
			// if any block in the existing confirmation queue is earlier than the tx block
			// the existing confirmation queue is no valid
			// we need to rebuild the confirmations queue
			occ.Rebuilt = true
			return newQueue[:1], currentBlock
		}

		// the existing confirmation queue is not tightly controlled by our canonical chain
		// ^^ even though it supposed to be build by a canonical chain, we cannot rely on it
		// because they are stored outside of current system
		// Therefore, we need to check whether the existing confirmation queue is corrupted
		isCorrupted := previousExistingConfirmation != nil &&
			(previousExistingConfirmation.BlockNumber.Uint64()+1 != existingConfirmation.BlockNumber.Uint64() ||
				previousExistingConfirmation.BlockHash != existingConfirmation.ParentHash) ||
			// check the link between the first confirmation block and the existing tx block
			(existingConfirmation.BlockNumber.Uint64() == txBlockNumber+1 &&
				existingConfirmation.ParentHash != txBlockInfo.BlockHash)
			//  we allow gaps between the tx block and the first block in the existing confirmation queue
			// NOTE: we don't allow gaps after the first block in the existing confirmation queue
			// any gaps, we need to rebuild the confirmations queue

		if isCorrupted {
			// any corruption in the existing confirmation queue will cause the confirmation queue to be rebuilt
			// we don't keep any of the existing confirmations
			occ.Rebuilt = true
			return newQueue[:1], currentBlock
		}

		currentBlockInfo := currentBlock.Value.(*ffcapi.MinimalBlockInfo)
		if existingConfirmation.BlockNumber.Uint64() < currentBlockInfo.BlockNumber.Uint64() {
			// NOTE: we are not doing the confirmation count check here
			// because we've not reached the current head in the canonical chain to validate
			// all the confirmations we copied over are still valid
			newQueue = append(newQueue, existingConfirmation)
			previousExistingConfirmation = existingConfirmation
			queueIndex++
			continue
		}

		if existingConfirmation.BlockNumber.Uint64() == currentBlockInfo.BlockNumber.Uint64() {
			// existing confirmation has caught up to the current block
			// checking the overlaps

			if !existingConfirmation.Equal(currentBlockInfo) {
				// we detected a potential fork
				if connectionBlockNumber == currentBlockInfo.BlockNumber.Uint64() &&
					!previousExistingConfirmation.IsParentOf(currentBlockInfo) {
					// this is the connection node (first overlap between existing confirmation queue and canonical chain)
					// if the first node doesn't chain to to the previous confirmation, it means all the historical confirmation are on a different fork
					// therefore, we need to rebuild the confirmations queue
					occ.Rebuilt = true
					return newQueue[:1], currentBlock
				}

				// other scenarios, the historical confirmation are still trustworthy and linked to our canonical chain
				occ.HasNewFork = true
				return newQueue, currentBlock
			}

			newQueue = append(newQueue, existingConfirmation)
			if existingConfirmation.BlockNumber.Uint64()-txBlockNumber >= targetConfirmationCount {
				break
			}
			currentBlock = currentBlock.Next()
			previousExistingConfirmation = existingConfirmation
			queueIndex++
			continue
		}

		occ.Rebuilt = true
		return newQueue[:1], currentBlock
	}

	// Check if we have enough confirmations
	lastBlockInNewQueue := newQueue[len(newQueue)-1]
	confirmationBlockNumber := txBlockNumber + targetConfirmationCount
	if lastBlockInNewQueue.BlockNumber.Uint64() >= confirmationBlockNumber {
		chainHead := bl.canonicalChain.Front().Value.(*ffcapi.MinimalBlockInfo)
		// we've got a confirmable so whether the rest of the chain has forked is not longer relevant
		// this could happen when user chose a different target confirmation count for the new checks
		// but we still need to validate the existing confirmations are connectable to the canonical chain
		// Check if the queue connects to the canonical chain
		if lastBlockInNewQueue.BlockNumber.Uint64() >= chainHead.BlockNumber.Uint64() ||
			(lastBlockInNewQueue.BlockNumber.Uint64() == chainHead.BlockNumber.Uint64()-1 &&
				lastBlockInNewQueue.BlockHash == chainHead.ParentHash) {
			occ.HasNewFork = false
			occ.HasNewConfirmation = false
			occ.Rebuilt = false
			occ.Confirmed = true

			// Trim the queue to only include blocks up to the max confirmation count
			trimmedQueue := []*ffcapi.MinimalBlockInfo{}
			for _, confirmation := range newQueue {
				if confirmation.BlockNumber.Uint64() > confirmationBlockNumber {
					break
				}
				trimmedQueue = append(trimmedQueue, confirmation)
			}

			// If we've trimmed off all the existing confirmations, we need to add the canonical chain head
			// to tell use the head block we used to confirmed the transaction
			if len(trimmedQueue) == 1 {
				trimmedQueue = append(trimmedQueue, chainHead)
			}
			return trimmedQueue, currentBlock
		}
	}

	return newQueue, currentBlock
}

func (bl *blockListener) buildNewConfirmations(occ *ffcapi.ConfirmationMapUpdateResult, newQueue []*ffcapi.MinimalBlockInfo, currentBlock *list.Element, txBlockNumber uint64, targetConfirmationCount uint64) []*ffcapi.MinimalBlockInfo {
	for currentBlock != nil {
		currentBlockInfo := currentBlock.Value.(*ffcapi.MinimalBlockInfo)
		if currentBlockInfo.BlockNumber.Uint64() > newQueue[len(newQueue)-1].BlockNumber.Uint64() {
			occ.HasNewConfirmation = true
			newQueue = append(newQueue, &ffcapi.MinimalBlockInfo{
				BlockHash:   currentBlockInfo.BlockHash,
				BlockNumber: fftypes.FFuint64(currentBlockInfo.BlockNumber.Uint64()),
				ParentHash:  currentBlockInfo.ParentHash,
			})
			if currentBlockInfo.BlockNumber.Uint64() >= txBlockNumber+targetConfirmationCount {
				occ.Confirmed = true
				break
			}
		}
		currentBlock = currentBlock.Next()
	}
	return newQueue
}

func (c *ethConnector) ReconcileConfirmationsForTransaction(ctx context.Context, txHash string, confirmMap *ffcapi.ConfirmationMap, targetConfirmationCount uint64) (*ffcapi.ConfirmationMapUpdateResult, error) {
	return c.blockListener.reconcileConfirmationsForTransaction(ctx, txHash, confirmMap, targetConfirmationCount)
}
