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

// The confirmation reconciler manages transaction confirmation queues by:
// - Copying blocks from the in-memory partial chain and the existing confirmation queue
// - Detecting blockchain forks and rebuilding confirmation queues when necessary
// - Filling gaps in confirmation queues by fetching missing blocks
// - Determining when transactions have reached the target confirmation count
package ethereum

import (
	"context"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// reconcileConfirmationsForTransaction reconciles the confirmation queue for a transaction
func (bl *blockListener) reconcileConfirmationsForTransaction(ctx context.Context, txHash string, existingConfirmations []*ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationUpdateResult, error) {
	// Initialize the result with existing confirmations
	reconcileResult := &ffcapi.ConfirmationUpdateResult{
		Confirmations:           existingConfirmations,
		NewFork:                 false,
		Confirmed:               false,
		TargetConfirmationCount: targetConfirmationCount,
	}

	// Fetch the block containing the transaction
	txBlockInfo, err := bl.getBlockInfoContainsTxHash(ctx, txHash)
	if err != nil {
		log.L(ctx).Errorf("Failed to fetch block info using tx hash %s: %v", txHash, err)
		return nil, err
	}

	if txBlockInfo == nil {
		log.L(ctx).Debugf("Transaction %s not found in any block", txHash)
		return nil, i18n.NewError(ctx, msgs.MsgTransactionNotFound, txHash)
	}

	return bl.compareAndUpdateConfirmationQueue(ctx, reconcileResult, txBlockInfo, targetConfirmationCount)
}

// compareAndUpdateConfirmationQueue orchestrates the confirmation reconciliation process.
// It builds new confirmations from the in-memory partial chain and fills gaps in the confirmation queue.
func (bl *blockListener) compareAndUpdateConfirmationQueue(ctx context.Context, reconcileResult *ffcapi.ConfirmationUpdateResult, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationUpdateResult, error) {

	// Initialize confirmation map and get existing confirmations
	// the init must happen after the in-memory partial chain check to avoid
	// confirming blocks that are not yet validated in the in-memory partial chain
	var existingConfirmations []*ffcapi.MinimalBlockInfo
	// If no existing confirmations, initialize with the transaction block
	if len(reconcileResult.Confirmations) == 0 {
		reconcileResult.Confirmations = []*ffcapi.MinimalBlockInfo{txBlockInfo}
		existingConfirmations = nil
	} else {
		// Validate existing confirmations against the current transaction block
		existingQueue := reconcileResult.Confirmations
		if len(existingQueue) > 0 {
			existingTxBlock := existingQueue[0]
			if !existingTxBlock.Equal(txBlockInfo) {
				// Transaction block mismatch indicates a fork - rebuild confirmation queue
				reconcileResult.NewFork = true
				reconcileResult.Confirmations = []*ffcapi.MinimalBlockInfo{txBlockInfo}
				existingConfirmations = nil
			} else {
				existingConfirmations = existingQueue
			}
		} else {
			existingConfirmations = existingQueue
		}
	}

	var err error
	// Build new confirmations from the in-memory partial chain and get existing confirmations
	newConfirmationsWithoutTxBlock, lastValidatedBlock, err := bl.buildConfirmationQueueUsingInMemoryPartialChain(ctx, txBlockInfo, targetConfirmationCount)
	if err != nil {
		return nil, err
	}

	// Special case: if targetConfirmationCount is 0, transaction is immediately confirmed
	if targetConfirmationCount == 0 {
		reconcileResult.Confirmations = []*ffcapi.MinimalBlockInfo{txBlockInfo}
		reconcileResult.Confirmed = true
		return reconcileResult, nil
	}

	// Validate existing confirmations and fill gaps in the confirmation queue
	var confirmations []*ffcapi.MinimalBlockInfo
	var newFork bool
	confirmations, newFork, err = bl.checkAndFillInGap(ctx, newConfirmationsWithoutTxBlock, existingConfirmations, txBlockInfo, targetConfirmationCount, lastValidatedBlock)
	if err != nil {
		return nil, err
	}
	reconcileResult.NewFork = newFork
	reconcileResult.Confirmations = confirmations
	reconcileResult.Confirmed = uint64(len(confirmations)) >= targetConfirmationCount+1
	return reconcileResult, err
}

// buildConfirmationQueueUsingInMemoryPartialChain builds the confirmation queue using the in-memory partial chain.
// It does not modify the in-memory partial chain itself, only reads from it.
// This function holds a read lock on the in-memory partial chain, so it should not make long-running queries.
func (bl *blockListener) buildConfirmationQueueUsingInMemoryPartialChain(ctx context.Context, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (newConfirmationsWithoutTxBlock []*ffcapi.MinimalBlockInfo, lastValidatedBlock *ffcapi.MinimalBlockInfo, err error) {
	bl.mux.RLock()
	defer bl.mux.RUnlock()
	txBlockNumber := txBlockInfo.BlockNumber.Uint64()
	targetBlockNumber := txBlockInfo.BlockNumber.Uint64() + targetConfirmationCount

	// Check if the in-memory partial chain has caught up to the transaction block
	chainTail := bl.canonicalChain.Back().Value.(*ffcapi.MinimalBlockInfo)
	if chainTail == nil || chainTail.BlockNumber.Uint64() < txBlockNumber {
		log.L(ctx).Debugf("in-memory partial chain is waiting for the transaction block %d to be indexed", txBlockNumber)
		return nil, nil, i18n.NewError(ctx, msgs.MsgInMemoryPartialChainNotCaughtUp, txBlockNumber, txBlockInfo.BlockHash)
	}

	// Build new confirmations from blocks after the transaction block

	newConfirmationsWithoutTxBlock = []*ffcapi.MinimalBlockInfo{}
	nextInMemoryBlock := bl.canonicalChain.Front()
	for nextInMemoryBlock != nil {
		nextInMemoryBlockInfo := nextInMemoryBlock.Value.(*ffcapi.MinimalBlockInfo)

		// If we've reached the target confirmation count, mark as confirmed
		if nextInMemoryBlockInfo.BlockNumber.Uint64() > targetBlockNumber {
			// if the in-memory partial chain contains the next block after the target block number,
			// and the new confirmations queue is empty,
			// we set the last validated block to the next block, so the downstream function can use it validate blocks before it
			if len(newConfirmationsWithoutTxBlock) == 0 && nextInMemoryBlockInfo.BlockNumber.Uint64() == targetBlockNumber+1 {
				lastValidatedBlock = nextInMemoryBlockInfo
			}
			break
		}

		// Skip blocks at or before the transaction block
		if nextInMemoryBlockInfo.BlockNumber.Uint64() <= txBlockNumber {
			nextInMemoryBlock = nextInMemoryBlock.Next()
			continue
		}

		// Add blocks after the transaction block to confirmations
		newConfirmationsWithoutTxBlock = append(newConfirmationsWithoutTxBlock, &ffcapi.MinimalBlockInfo{
			BlockHash:   nextInMemoryBlockInfo.BlockHash,
			BlockNumber: fftypes.FFuint64(nextInMemoryBlockInfo.BlockNumber.Uint64()),
			ParentHash:  nextInMemoryBlockInfo.ParentHash,
		})
		nextInMemoryBlock = nextInMemoryBlock.Next()
	}
	return newConfirmationsWithoutTxBlock, lastValidatedBlock, nil
}

// checkAndFillInGap validates existing confirmations, detects forks, and fills gaps
// in the confirmation queue using existing confirmations or fetching missing blocks from the blockchain.
// It ensures the confirmation chain is valid and connected to the transaction block.
func (bl *blockListener) checkAndFillInGap(ctx context.Context, newConfirmationsWithoutTxBlock []*ffcapi.MinimalBlockInfo, existingConfirmations []*ffcapi.MinimalBlockInfo, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64, lastValidatedBlock *ffcapi.MinimalBlockInfo) ([]*ffcapi.MinimalBlockInfo, bool, error) {
	var hasNewFork bool

	// Detect forks by comparing new confirmations with existing ones
	for _, confirmation := range newConfirmationsWithoutTxBlock {
		for _, existingConfirmation := range existingConfirmations {
			if confirmation.BlockNumber.Uint64() == existingConfirmation.BlockNumber.Uint64() && !confirmation.Equal(existingConfirmation) {
				hasNewFork = true
				break
			}
		}
		if hasNewFork {
			break
		}
	}

	// Determine the range of blocks to validate and fill gaps
	blockNumberToReach := txBlockInfo.BlockNumber.Uint64() + targetConfirmationCount
	if len(newConfirmationsWithoutTxBlock) > 0 {
		// Start from the block before the first new confirmation
		blockNumberToReach = newConfirmationsWithoutTxBlock[0].BlockNumber.Uint64() - 1
		lastValidatedBlock = newConfirmationsWithoutTxBlock[0]
	}

	// Fill gaps by validating blocks from target down to transaction block
	for i := blockNumberToReach; i > txBlockInfo.BlockNumber.Uint64(); i-- {
		fetchedFromExistingQueue := false

		// First, try to use existing confirmations if they match
		if lastValidatedBlock != nil {
			for _, confirmation := range existingConfirmations {
				if confirmation.BlockNumber.Uint64() == i {
					if confirmation.IsParentOf(lastValidatedBlock) {
						// Valid existing confirmation - prepend to queue
						newConfirmationsWithoutTxBlock = append([]*ffcapi.MinimalBlockInfo{confirmation}, newConfirmationsWithoutTxBlock...)
						lastValidatedBlock = confirmation
						fetchedFromExistingQueue = true
						break
					}
					// Block number matches but parent relationship is invalid - fork detected
					hasNewFork = true
				}
			}
		}

		if fetchedFromExistingQueue {
			continue
		}

		// Fetch block from blockchain if not found in existing confirmations
		freshBlockInfo, _, err := bl.getBlockInfoByNumber(ctx, i, false, "", "")
		if err != nil {
			return nil, hasNewFork, err
		}
		if freshBlockInfo == nil {
			return nil, hasNewFork, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
		}

		fetchedBlock := &ffcapi.MinimalBlockInfo{
			BlockNumber: fftypes.FFuint64(freshBlockInfo.Number.BigInt().Uint64()),
			BlockHash:   freshBlockInfo.Hash.String(),
			ParentHash:  freshBlockInfo.ParentHash.String(),
		}

		// Validate parent-child relationship
		if lastValidatedBlock != nil && !fetchedBlock.IsParentOf(lastValidatedBlock) {
			return nil, hasNewFork, i18n.NewError(ctx, msgs.MsgFailedToBuildConfirmationQueue)
		}

		// Prepend fetched block to confirmation queue
		newConfirmationsWithoutTxBlock = append([]*ffcapi.MinimalBlockInfo{fetchedBlock}, newConfirmationsWithoutTxBlock...)
		lastValidatedBlock = fetchedBlock
	}

	// Final validation: ensure the confirmation chain connects to the transaction block
	if len(newConfirmationsWithoutTxBlock) > 0 && !txBlockInfo.IsParentOf(newConfirmationsWithoutTxBlock[0]) {
		return nil, hasNewFork, i18n.NewError(ctx, msgs.MsgFailedToBuildConfirmationQueue)
	}

	return append([]*ffcapi.MinimalBlockInfo{txBlockInfo}, newConfirmationsWithoutTxBlock...), hasNewFork, nil
}

// ReconcileConfirmationsForTransaction is the public API for reconciling transaction confirmations.
// It delegates to the blockListener's internal reconciliation logic.
func (c *ethConnector) ReconcileConfirmationsForTransaction(ctx context.Context, txHash string, existingConfirmations []*ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationUpdateResult, error) {
	return c.blockListener.reconcileConfirmationsForTransaction(ctx, txHash, existingConfirmations, targetConfirmationCount)
}
