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
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-transaction-manager/pkg/apitypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

type ConfirmationMapUpdateResult struct {
	*ConfirmationMap
	HasNewFork              bool `json:"hasNewFork"`              // when set to true, it means a fork is detected based on the existing confirmations
	Rebuilt                 bool `json:"rebuilt"`                 // when set to true, it means all of the existing confirmations are discarded
	HasNewConfirmation      bool `json:"hasNewConfirmation"`      // when set to true, it means new blocks from canonical chain are added to the confirmation queue
	Confirmed               bool `json:"confirmed"`               // when set to true, it means the confirmation queue is complete and all the blocks are confirmed
	TargetConfirmationCount int  `json:"targetConfirmationCount"` // the target number of confirmations for this event
}

type ConfirmationMap struct {
	// confirmation map is contains a list of possible confirmations for a transaction
	// the key is the hash of the first block that contains the transaction hash
	// the first block is the block that contains the transaction hash
	ConfirmationQueueMap map[string][]*apitypes.Confirmation `json:"confirmationQueueMap,omitempty"`
	// which block hash that leads a confirmation queue matches the canonical block hash
	CanonicalBlockHash string `json:"canonicalBlockHash,omitempty"`
}

func (bl *blockListener) BuildConfirmationsForTransaction(ctx context.Context, txHash string, confirmMap *ConfirmationMap, targetConfirmationCount int) (*ConfirmationMapUpdateResult, error) {
	// Initialize the output context
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap:         confirmMap,
		HasNewFork:              false,
		Rebuilt:                 false,
		HasNewConfirmation:      false,
		Confirmed:               false,
		TargetConfirmationCount: targetConfirmationCount,
	}

	// Query the chain to find the transaction block
	// Note: should consider have an in-memory map of transaction hash to block for faster lookup
	// The extra memory usage of the map should be outweighed by the speed of lookup
	// But I saw we have a minimalBlockInfo struct that intentionally removes the tx hashes
	// so need to figure out the reason first

	res, reason, receiptErr := bl.c.TransactionReceipt(ctx, &ffcapi.TransactionReceiptRequest{
		TransactionHash: txHash,
	})
	if receiptErr != nil || res == nil {
		if receiptErr != nil && reason != ffcapi.ErrorReasonNotFound {
			log.L(ctx).Debugf("Failed to query receipt for transaction %s: %s", txHash, receiptErr)
			return nil, i18n.WrapError(ctx, receiptErr, msgs.MsgFailedToQueryReceipt, txHash)
		}
		log.L(ctx).Debugf("Receipt for transaction %s not yet available: %v", txHash, receiptErr)
		return nil, i18n.WrapError(ctx, receiptErr, msgs.MsgFailedToQueryReceipt, txHash)
	}

	txBlockHash := res.BlockHash
	txBlockNumber := res.BlockNumber.Int64()
	// get the parent hash of the transaction block
	bi, _, err := bl.getBlockInfoByNumber(ctx, txBlockNumber, true, txBlockHash)
	if err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgFailedToQueryBlockInfo, txHash)
	}
	txBlockInfo := &minimalBlockInfo{
		number:     bi.Number.BigInt().Int64(),
		hash:       bi.Hash.String(),
		parentHash: bi.ParentHash.String(),
	}

	// Compare the existing confirmation queue with the in-memory linked list
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	return occ, nil
}

// NOTE: this function only build up the confirmation queue uses the in-memory canonical chain
// it does not build up the canonical chain
// compareAndUpdateConfirmationQueue compares the existing confirmation queue with the in-memory linked list

func (bl *blockListener) compareAndUpdateConfirmationQueue(ctx context.Context, occ *ConfirmationMapUpdateResult, txBlockInfo *minimalBlockInfo, targetConfirmationCount int) {
	bl.mux.RLock()
	defer bl.mux.RUnlock()
	txBlockNumber := txBlockInfo.number
	txBlockHash := txBlockInfo.hash

	chainHead := bl.canonicalChain.Front().Value.(*minimalBlockInfo)
	chainTail := bl.canonicalChain.Back().Value.(*minimalBlockInfo)
	if chainHead == nil || chainTail == nil || chainTail.number < txBlockNumber {
		log.L(ctx).Debugf("Canonical chain is waiting for the transaction block %d to be indexed", txBlockNumber)
		return
	}

	// Initialize confirmation map and get existing queue
	existingQueue := bl.initializeConfirmationMap(occ, txBlockInfo)

	// Validate and process existing confirmations
	newQueue, currentBlock := bl.processExistingConfirmations(ctx, occ, txBlockInfo, existingQueue, chainHead, targetConfirmationCount)

	// Build new confirmations from canonical chain only if not already confirmed
	if !occ.Confirmed {
		newQueue = bl.buildNewConfirmations(occ, newQueue, currentBlock, txBlockNumber, targetConfirmationCount)
	}
	occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash] = newQueue
}

func (bl *blockListener) initializeConfirmationMap(occ *ConfirmationMapUpdateResult, txBlockInfo *minimalBlockInfo) []*apitypes.Confirmation {
	txBlockHash := txBlockInfo.hash

	if occ.ConfirmationMap == nil || len(occ.ConfirmationMap.ConfirmationQueueMap) == 0 {
		occ.ConfirmationMap = &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				txBlockHash: {txBlockInfo.ToConfirmation()},
			},
			CanonicalBlockHash: txBlockHash,
		}
		occ.HasNewFork = true
		return nil
	}

	existingQueue := occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash]
	if len(existingQueue) > 0 {
		existingTxBlock := existingQueue[0]
		if !isSameBlock(existingTxBlock, txBlockInfo) {
			// the tx block in the existing queue does not match the new tx block we queried from the chain
			// rebuild a new confirmation queue with the new tx block
			occ.HasNewFork = true
			occ.Rebuilt = true
			occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash] = []*apitypes.Confirmation{txBlockInfo.ToConfirmation()}
			return nil
		}
	}

	return existingQueue
}

func (bl *blockListener) processExistingConfirmations(ctx context.Context, occ *ConfirmationMapUpdateResult, txBlockInfo *minimalBlockInfo, existingQueue []*apitypes.Confirmation, chainHead *minimalBlockInfo, targetConfirmationCount int) ([]*apitypes.Confirmation, *list.Element) {
	txBlockNumber := txBlockInfo.number

	newQueue := []*apitypes.Confirmation{txBlockInfo.ToConfirmation()}

	currentBlock := bl.canonicalChain.Front()
	// iterate to the tx block if the chain head is earlier than the tx block
	if currentBlock != nil && currentBlock.Value.(*minimalBlockInfo).number <= txBlockNumber {
		currentBlock = currentBlock.Next()
	}

	if len(existingQueue) == 0 {
		return newQueue, currentBlock
	}

	existingConfirmations := existingQueue[1:]
	if len(existingConfirmations) == 0 {
		return newQueue, currentBlock
	}

	return bl.validateExistingConfirmations(ctx, occ, newQueue, existingConfirmations, currentBlock, chainHead, txBlockInfo, targetConfirmationCount)
}

func (bl *blockListener) validateExistingConfirmations(ctx context.Context, occ *ConfirmationMapUpdateResult, newQueue []*apitypes.Confirmation, existingConfirmations []*apitypes.Confirmation, currentBlock *list.Element, chainHead *minimalBlockInfo, txBlockInfo *minimalBlockInfo, targetConfirmationCount int) ([]*apitypes.Confirmation, *list.Element) {
	txBlockNumber := txBlockInfo.number
	lastExistingConfirmation := existingConfirmations[len(existingConfirmations)-1]
	if lastExistingConfirmation.BlockNumber.Uint64() < uint64(chainHead.number) && //nolint:gosec
		// ^^ the highest block number in the existing confirmations is lower than the highest block number in the canonical chain
		(lastExistingConfirmation.BlockNumber.Uint64() != uint64(chainHead.number-1) || //nolint:gosec // block numbers are always positive
			lastExistingConfirmation.BlockHash != chainHead.parentHash) {
		// ^^ and the last existing confirmation is not the parent of the canonical chain head
		// Therefore, there is no connection between the existing confirmations and the canonical chain
		// so that we cannot validate the existing confirmations are from the same fork as the canonical chain
		// so we need to rebuild the confirmations queue
		occ.Rebuilt = true
		return newQueue, currentBlock
	}

	var previousExistingConfirmation *apitypes.Confirmation
	queueIndex := 0

	connectionBlockNumber := currentBlock.Value.(*minimalBlockInfo).number

	for currentBlock != nil && queueIndex < len(existingConfirmations) {
		existingConfirmation := existingConfirmations[queueIndex]
		if existingConfirmation.BlockNumber.Uint64() <= uint64(txBlockNumber) { //nolint:gosec // block numbers are always positive
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
			(existingConfirmation.BlockNumber.Uint64() == uint64(txBlockNumber)+1 && //nolint:gosec // block numbers are always positive
				existingConfirmation.ParentHash != txBlockInfo.hash)
			//  we allow gaps between the tx block and the first block in the existing confirmation queue
			// NOTE: we don't allow gaps after the first block in the existing confirmation queue
			// any gaps, we need to rebuild the confirmations queue

		if isCorrupted {
			// any corruption in the existing confirmation queue will cause the confirmation queue to be rebuilt
			// we don't keep any of the existing confirmations
			occ.Rebuilt = true
			return newQueue[:1], currentBlock
		}

		currentBlockInfo := currentBlock.Value.(*minimalBlockInfo)
		if existingConfirmation.BlockNumber.Uint64() < uint64(currentBlockInfo.number) { //nolint:gosec
			// NOTE: we are not doing the confirmation count check here
			// because we've not reached the current head in the canonical chain to validate
			// all the confirmations we copied over are still valid
			newQueue = append(newQueue, existingConfirmation)
			previousExistingConfirmation = existingConfirmation
			queueIndex++
			continue
		}

		if existingConfirmation.BlockNumber.Uint64() == uint64(currentBlockInfo.number) { //nolint:gosec // block numbers are always positive
			// existing confirmation has caught up to the current block
			// checking the overlaps

			if !isSameBlock(existingConfirmation, currentBlockInfo) {
				// we detected a potential fork
				if connectionBlockNumber == currentBlockInfo.number &&
					previousExistingConfirmation.BlockHash != currentBlockInfo.parentHash {
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
			if existingConfirmation.BlockNumber.Uint64()-uint64(txBlockNumber) >= uint64(targetConfirmationCount) { //nolint:gosec // block numbers are always positive
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
	confirmationBlockNumber := uint64(txBlockNumber) + uint64(targetConfirmationCount) //nolint:gosec // block numbers are always positive
	if lastBlockInNewQueue.BlockNumber.Uint64() >= confirmationBlockNumber {
		chainHead := bl.canonicalChain.Front().Value.(*minimalBlockInfo)
		// we've got a confirmable so whether the rest of the chain has forked is not longer relevant
		// this could happen when user chose a different target confirmation count for the new checks
		// but we still need to validate the existing confirmations are connectable to the canonical chain
		// Check if the queue connects to the canonical chain
		if lastBlockInNewQueue.BlockNumber.Uint64() >= uint64(chainHead.number) || //nolint:gosec // block numbers are always positive
			(lastBlockInNewQueue.BlockNumber.Uint64() == uint64(chainHead.number-1) && //nolint:gosec // block numbers are always positive
				lastBlockInNewQueue.BlockHash == chainHead.parentHash) {
			occ.HasNewFork = false
			occ.HasNewConfirmation = false
			occ.Rebuilt = false
			occ.Confirmed = true

			// Trim the queue to only include blocks up to the max confirmation count
			trimmedQueue := []*apitypes.Confirmation{}
			for _, confirmation := range newQueue {
				if confirmation.BlockNumber.Uint64() > confirmationBlockNumber {
					break
				}
				trimmedQueue = append(trimmedQueue, confirmation)
			}

			// If we've trimmed off all the existing confirmations, we need to add the canonical chain head
			// to tell use the head block we used to confirmed the transaction
			if len(trimmedQueue) == 1 {
				trimmedQueue = append(trimmedQueue, chainHead.ToConfirmation())
			}
			return trimmedQueue, currentBlock
		}
	}

	return newQueue, currentBlock
}

func (bl *blockListener) buildNewConfirmations(occ *ConfirmationMapUpdateResult, newQueue []*apitypes.Confirmation, currentBlock *list.Element, txBlockNumber int64, targetConfirmationCount int) []*apitypes.Confirmation {
	for currentBlock != nil {
		currentBlockInfo := currentBlock.Value.(*minimalBlockInfo)
		if currentBlockInfo.number > int64(newQueue[len(newQueue)-1].BlockNumber.Uint64()) { //nolint:gosec // block numbers are always positive
			occ.HasNewConfirmation = true
			newQueue = append(newQueue, &apitypes.Confirmation{
				BlockHash:   currentBlockInfo.hash,
				BlockNumber: fftypes.FFuint64(currentBlockInfo.number), //nolint:gosec // block numbers are always positive
				ParentHash:  currentBlockInfo.parentHash,
			})
			if currentBlockInfo.number >= txBlockNumber+int64(targetConfirmationCount) { //nolint:gosec // block numbers are always positive
				occ.Confirmed = true
				break
			}
		}
		currentBlock = currentBlock.Next()
	}
	return newQueue
}

func isSameBlock(c1 *apitypes.Confirmation, bi *minimalBlockInfo) bool {
	return c1.BlockHash == bi.hash &&
		c1.BlockNumber.Uint64() == uint64(bi.number) && //nolint:gosec // block numbers are always positive
		c1.ParentHash == bi.parentHash
}
