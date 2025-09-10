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
		// we cannot build any useful confirmation information yet, so return the existing confirmation map
		return
	}
	var existingQueue []*apitypes.Confirmation
	if occ.ConfirmationMap == nil || len(occ.ConfirmationMap.ConfirmationQueueMap) == 0 {
		occ.ConfirmationMap = &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				txBlockHash: {&apitypes.Confirmation{
					BlockHash:   txBlockHash,
					BlockNumber: fftypes.FFuint64(txBlockNumber), //nolint:gosec // block numbers are always positive
					ParentHash:  txBlockInfo.parentHash,
				}},
			},
			CanonicalBlockHash: txBlockHash,
		}
		// starting a new confirmation queue
		occ.HasNewFork = true
	} else {
		existingQueue = occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash]
	}

	var existingConfirmations []*apitypes.Confirmation
	var previousExistingConfirmation *apitypes.Confirmation

	// get the first item of the confirmation queue
	// and compare with the transaction block
	if len(existingQueue) > 0 {
		if existingQueue[0].BlockNumber.Uint64() != uint64(txBlockNumber) { //nolint:gosec // block numbers are always positive
			// the existing queue of the current txBlockHash does not have the same block number as the new transaction block
			// clear the accumulated confirmation queue
			occ.HasNewFork = true
			occ.Rebuilt = true
			occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash] = []*apitypes.Confirmation{{
				BlockHash:   txBlockHash,
				BlockNumber: fftypes.FFuint64(txBlockNumber), //nolint:gosec // block numbers are always positive
				ParentHash:  txBlockInfo.parentHash,
			}}

		} else {
			existingConfirmations = existingQueue[1:]
			if len(existingConfirmations) > 0 {
				// check whether the first item in the existing confirmation queue is the next block of the tx block
				if existingConfirmations[0].BlockNumber.Uint64() == uint64(txBlockNumber)+1 { //nolint:gosec // block numbers are always positive
					// if it is, set the previous existing confirmation to the first item
					previousExistingConfirmation = existingQueue[0]
				}
				// otherwise, don't set the previous existing confirmation
				// as we allow gaps between the tx block and the first block in the existing confirmation queue
				// NOTE: we don't allow gaps after the first block in the existing confirmation queue
				// any gaps, we need to rebuild the confirmations queue
			}
		}
	}
	// now start building the new confirmation queue
	newQueue := []*apitypes.Confirmation{{
		BlockHash:   txBlockHash,
		BlockNumber: fftypes.FFuint64(txBlockNumber), //nolint:gosec // block numbers are always positive
		ParentHash:  txBlockInfo.parentHash,
	}}

	// NOTE: the current block might be moved forward as apart of the existing confirmations check
	currentBlock := bl.canonicalChain.Front()
	// iterate to the tx block if the chain head is earlier than the tx block
	if currentBlock != nil && currentBlock.Value.(*minimalBlockInfo).number <= txBlockNumber {
		currentBlock = currentBlock.Next()
	}

	// NOTE: we assume the first block in the existing confirmation is the lowest block number
	// and the last block in the existing confirmation is the highest block number
	// check whether the tail of existing confirmations connects to the existing canonical chain
	if len(existingConfirmations) > 0 {
		lastExistingConfirmation := existingConfirmations[len(existingConfirmations)-1]
		if lastExistingConfirmation.BlockNumber.Uint64() < uint64(chainHead.number) && //nolint:gosec // block numbers are always positive
			(lastExistingConfirmation.BlockNumber.Uint64() != uint64(chainHead.number-1) || //nolint:gosec // block numbers are always positive
				lastExistingConfirmation.BlockHash != chainHead.parentHash) {
			// there is no connection between the existing confirmations and the canonical chain
			// so we don't need to copy over any of the existing confirmations
			// as we won't be able to validate whether they are from the same fork as
			// the canonical chain
			occ.Rebuilt = true
		} else {
			// otherwise, the existing confirmations do have overlap with the canonical chain
			// so we can give a better view on whether this is a new fork or has new confirmations
			queueIndex := 0
			for currentBlock != nil && queueIndex < len(existingConfirmations) {
				existingConfirmation := existingConfirmations[queueIndex]
				// if any block in the existing confirmation queue is earlier than the tx block
				// we need to discard the existing confirmations
				if existingConfirmation.BlockNumber.Uint64() <= uint64(txBlockNumber) { //nolint:gosec // block numbers are always positive
					occ.Rebuilt = true
					newQueue = newQueue[:1]
					break
				}
				// the existing confirmation queue is not tightly controlled by our canonical chain
				// so we need to check whether the existing confirmation queue is corrupted
				isExistingBlockCorrupted := previousExistingConfirmation != nil &&
					(previousExistingConfirmation.BlockNumber.Uint64()+1 != existingConfirmation.BlockNumber.Uint64() ||
						previousExistingConfirmation.BlockHash != existingConfirmation.ParentHash)
				currentBlockInfo := currentBlock.Value.(*minimalBlockInfo)
				if isExistingBlockCorrupted {
					// the existing confirmation queue is corrupted
					// so we need to clear out the existing confirmations we copied over
					occ.Rebuilt = true
					newQueue = newQueue[:1]
					break
				}
				if existingConfirmation.BlockNumber.Uint64() < uint64(currentBlockInfo.number) { //nolint:gosec // block numbers are always positive
					// the existing confirmation is earlier than the current block

					// otherwise, we need to add the existing confirmation to the new queue
					// NOTE: we are not doing the confirmation count check here
					// because we've not reached the current head in the canonical chain to validate
					// all the confirmations we copied over are still valid
					newQueue = append(newQueue, existingConfirmation)
					previousExistingConfirmation = existingConfirmation
					queueIndex++
					continue
				} else if existingConfirmation.BlockNumber.Uint64() == uint64(currentBlockInfo.number) { //nolint:gosec // block numbers are always positive
					// existing confirmation has caught up to the current block
					// we also need to check the parent hash matches to decide
					// whether the existing confirmations added are still valid
					if previousExistingConfirmation.BlockHash != currentBlockInfo.parentHash {
						// this indicates a fork that happened before the current block
						// so all the previous carried over confirmations are invalid and needs to be cleared out
						occ.Rebuilt = true
						newQueue = newQueue[:1]
						// not adding the current block and do confirmation count check here
						// the downstream logic handle all the block addition of the new fork
						break
					} else if existingConfirmation.BlockHash != currentBlockInfo.hash {
						// this indicate the existing confirmation cannot be used, thus all the following confirmations are invalid
						occ.HasNewFork = true
						break
					}
					// otherwise, we need to add the existing confirmation to the new queue
					newQueue = append(newQueue, existingConfirmation)

					// if the target confirmation count has been reached
					if existingConfirmation.BlockNumber.Uint64()-uint64(txBlockNumber) >= uint64(targetConfirmationCount) { //nolint:gosec // block numbers are always positive
						// there is a chance the new queue contains more blocks than the target confirmation count
						break
					}
					// move to the next block for checking overlap
					currentBlock = currentBlock.Next()
					previousExistingConfirmation = existingConfirmation
					queueIndex++
					continue
				}
				// the existing confirmation is later than the current block
				// it means we have gaps to fill in, therefore, we need to replace the old confirmations
				// and don't bother with what's in the existing confirmation already
				occ.Rebuilt = true
				newQueue = newQueue[:1]
				break
			}
			// we've just iterated through all the existing confirmations
			// now we need to check whether we've got a confirmable queue
			lastBlockInNewQueue := newQueue[len(newQueue)-1]                                                       // at this point, it's guaranteed to be the highest block number
			if lastBlockInNewQueue.BlockNumber.Uint64() >= uint64(txBlockNumber)+uint64(targetConfirmationCount) { //nolint:gosec // block numbers are always positive
				// we've got a confirmable so whether the rest of the chain has forked is not longer relevant
				// this could happen when user chose a different target confirmation count for the new checks
				// but we still need to validate the existing confirmations are connectable to the canonical chain
				if lastBlockInNewQueue.BlockNumber.Uint64() >= uint64(chainHead.number) || //nolint:gosec // block numbers are always positive
					(lastBlockInNewQueue.BlockNumber.Uint64() == uint64(chainHead.number-1) && //nolint:gosec // block numbers are always positive
						lastBlockInNewQueue.BlockHash == chainHead.parentHash) {
					occ.HasNewFork = false
					occ.HasNewConfirmation = false
					occ.Rebuilt = false
					occ.Confirmed = true
					if lastBlockInNewQueue.BlockNumber.Uint64() == uint64(chainHead.number-1) && //nolint:gosec // block numbers are always positive
						lastBlockInNewQueue.BlockHash == chainHead.parentHash {
						newQueue = append(newQueue, &apitypes.Confirmation{
							BlockHash:   chainHead.hash,
							BlockNumber: fftypes.FFuint64(chainHead.number), //nolint:gosec // block numbers are always positive
							ParentHash:  chainHead.parentHash,
						})
					}
					// note: we don't trim the queue
					occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash] = newQueue
					return
				}
			}
		}
	}

	// at this point, we know the following:
	// 1. the existing confirmations that we copied over are valid
	// 2. the new queue is not confirmable just using the existing confirmations

	for currentBlock != nil {
		currentBlockInfo := currentBlock.Value.(*minimalBlockInfo)
		// only add the blocks that are later than the last block in the newQueue
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
	occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash] = newQueue
}
