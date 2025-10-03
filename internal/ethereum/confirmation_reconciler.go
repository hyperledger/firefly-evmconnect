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
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (bl *blockListener) reconcileConfirmationsForTransaction(ctx context.Context, txHash string, existingConfirmations []*ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationMapUpdateResult, error) {
	// Initialize the output context
	reconcileResult := &ffcapi.ConfirmationMapUpdateResult{
		Confirmations:           existingConfirmations,
		NewFork:                 false,
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
		return reconcileResult, nil
	}

	return bl.compareAndUpdateConfirmationQueue(ctx, reconcileResult, txBlockInfo, targetConfirmationCount)
}

func (bl *blockListener) compareAndUpdateConfirmationQueue(ctx context.Context, reconcileResult *ffcapi.ConfirmationMapUpdateResult, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationMapUpdateResult, error) {
	var err error
	// Compare the and build the tail part of the confirmation queue using the canonical chain
	newConfirmationsWithoutTxBlock, existingConfirmations, returnResult := bl.buildConfirmationQueueUsingCanonicalChain(ctx, reconcileResult, txBlockInfo, targetConfirmationCount)
	if returnResult {
		return reconcileResult, nil
	}

	// Validate and process existing confirmations
	// and fill in the gap in the confirmation queue
	var confirmations []*ffcapi.MinimalBlockInfo
	var newFork bool
	confirmations, newFork, err = bl.checkAndFillInGap(ctx, newConfirmationsWithoutTxBlock, existingConfirmations, txBlockInfo, targetConfirmationCount)
	if err != nil {
		return reconcileResult, err
	}
	reconcileResult.NewFork = newFork
	reconcileResult.Confirmations = confirmations
	return reconcileResult, err
}

// NOTE: this function only build up the confirmation queue uses the in-memory canonical chain
// it does not build up the canonical chain
// compareAndUpdateConfirmationQueueUsingCanonicalChain compares the existing confirmation queue with the in-memory linked list
// this function obtains the read lock on the canonical chain, so it should not make any long-running queries

func (bl *blockListener) buildConfirmationQueueUsingCanonicalChain(ctx context.Context, reconcileResult *ffcapi.ConfirmationMapUpdateResult, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (newConfirmationsWithoutTxBlock []*ffcapi.MinimalBlockInfo, existingConfirmations []*ffcapi.MinimalBlockInfo, returnResult bool) {
	bl.mux.RLock()
	defer bl.mux.RUnlock()
	txBlockNumber := txBlockInfo.BlockNumber.Uint64()
	targetBlockNumber := txBlockInfo.BlockNumber.Uint64() + targetConfirmationCount

	chainTail := bl.canonicalChain.Back().Value.(*ffcapi.MinimalBlockInfo)
	if chainTail == nil || chainTail.BlockNumber.Uint64() < txBlockNumber {
		log.L(ctx).Debugf("Canonical chain is waiting for the transaction block %d to be indexed", txBlockNumber)
		return nil, nil, true
	}

	// Initialize confirmation map and get existing queue
	existingConfirmations = bl.initializeConfirmationMap(reconcileResult, txBlockInfo)

	// if the target confirmation count is 0, we should just return the transaction block
	if targetConfirmationCount == 0 {
		reconcileResult.Confirmed = true
		reconcileResult.Confirmations = []*ffcapi.MinimalBlockInfo{txBlockInfo}
		return nil, existingConfirmations, true
	}

	// build the tail part of the queue from the canonical chain

	newConfirmationsWithoutTxBlock = []*ffcapi.MinimalBlockInfo{}
	currentBlock := bl.canonicalChain.Front()
	for currentBlock != nil {
		currentBlockInfo := currentBlock.Value.(*ffcapi.MinimalBlockInfo)
		if currentBlockInfo.BlockNumber.Uint64() > targetBlockNumber {
			reconcileResult.Confirmed = true
			break
		}
		if currentBlockInfo.BlockNumber.Uint64() <= txBlockNumber {
			currentBlock = currentBlock.Next()
			continue
		}
		newConfirmationsWithoutTxBlock = append(newConfirmationsWithoutTxBlock, &ffcapi.MinimalBlockInfo{
			BlockHash:   currentBlockInfo.BlockHash,
			BlockNumber: fftypes.FFuint64(currentBlockInfo.BlockNumber.Uint64()),
			ParentHash:  currentBlockInfo.ParentHash,
		})
		currentBlock = currentBlock.Next()
	}
	return newConfirmationsWithoutTxBlock, existingConfirmations, false
}

func (bl *blockListener) initializeConfirmationMap(reconcileResult *ffcapi.ConfirmationMapUpdateResult, txBlockInfo *ffcapi.MinimalBlockInfo) []*ffcapi.MinimalBlockInfo {
	if len(reconcileResult.Confirmations) == 0 {
		reconcileResult.Confirmations = []*ffcapi.MinimalBlockInfo{txBlockInfo}
		return nil
	}

	existingQueue := reconcileResult.Confirmations
	if len(existingQueue) > 0 {
		existingTxBlock := existingQueue[0]
		if !existingTxBlock.Equal(txBlockInfo) {
			// the tx block in the existing queue does not match the new tx block we queried from the chain
			// rebuild a new confirmation queue with the new tx block
			reconcileResult.NewFork = true
			reconcileResult.Confirmations = []*ffcapi.MinimalBlockInfo{txBlockInfo}
			return nil
		}
	}

	return existingQueue
}

func (bl *blockListener) checkAndFillInGap(ctx context.Context, newConfirmationsWithoutTxBlock []*ffcapi.MinimalBlockInfo, existingConfirmations []*ffcapi.MinimalBlockInfo, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) ([]*ffcapi.MinimalBlockInfo, bool, error) {
	var hasNewFork bool
	// check whether there are forks in the newConfirmations
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

	blockNumberToReach := txBlockInfo.BlockNumber.Uint64() + targetConfirmationCount
	var lastValidatedBlock *ffcapi.MinimalBlockInfo
	if len(newConfirmationsWithoutTxBlock) > 0 {
		blockNumberToReach = newConfirmationsWithoutTxBlock[0].BlockNumber.Uint64() - 1
		lastValidatedBlock = newConfirmationsWithoutTxBlock[0]
	}

	for i := blockNumberToReach; i > txBlockInfo.BlockNumber.Uint64(); i-- {
		// first use the block info from the confirmation queue if matches are found
		fetchedFromExistingQueue := false
		if lastValidatedBlock != nil {

			for _, confirmation := range existingConfirmations {
				if confirmation.BlockNumber.Uint64() == i {
					if confirmation.IsParentOf(lastValidatedBlock) {
						newConfirmationsWithoutTxBlock = append([]*ffcapi.MinimalBlockInfo{confirmation}, newConfirmationsWithoutTxBlock...)
						lastValidatedBlock = confirmation
						fetchedFromExistingQueue = true
						break
					}
					hasNewFork = true
				}
			}
		}
		if fetchedFromExistingQueue {
			continue
		}
		// if no match is found, fetch the block info from the chain
		freshBlockInfo, _, err := bl.getBlockInfoByNumber(ctx, i, false, "", "")
		if err != nil {
			return nil, hasNewFork, err
		}
		fetchedBlock := &ffcapi.MinimalBlockInfo{
			BlockNumber: fftypes.FFuint64(freshBlockInfo.Number.BigInt().Uint64()),
			BlockHash:   freshBlockInfo.Hash.String(),
			ParentHash:  freshBlockInfo.ParentHash.String(),
		}
		if lastValidatedBlock != nil && !fetchedBlock.IsParentOf(lastValidatedBlock) {
			// the fetched block is not the parent of the last validated block
			// chain is not in a stable stable to build the confirmation queue
			return nil, hasNewFork, i18n.NewError(ctx, msgs.MsgFailedToBuildConfirmationQueue)
		}
		newConfirmationsWithoutTxBlock = append([]*ffcapi.MinimalBlockInfo{fetchedBlock}, newConfirmationsWithoutTxBlock...)
		lastValidatedBlock = fetchedBlock
	}

	// we've rebuilt the confirmations queue, now check the front of the queue still connect to the tx block
	if !txBlockInfo.IsParentOf(newConfirmationsWithoutTxBlock[0]) {
		return nil, hasNewFork, i18n.NewError(ctx, msgs.MsgFailedToBuildConfirmationQueue)
	}
	return append([]*ffcapi.MinimalBlockInfo{txBlockInfo}, newConfirmationsWithoutTxBlock...), hasNewFork, nil
}

func (c *ethConnector) ReconcileConfirmationsForTransaction(ctx context.Context, txHash string, existingConfirmations []*ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationMapUpdateResult, error) {
	return c.blockListener.reconcileConfirmationsForTransaction(ctx, txHash, existingConfirmations, targetConfirmationCount)
}
