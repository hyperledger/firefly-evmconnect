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

// ReconcileConfirmationsForTransaction is the public API for reconciling transaction confirmations.
// It delegates to the blockListener's internal reconciliation logic.
func (c *ethConnector) ReconcileConfirmationsForTransaction(ctx context.Context, txHash string, existingConfirmations []*ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationUpdateResult, error) {

	// Before we start, make sure that the existing confirmations queue is valid and consistent with itself
	err := validateExistingConfirmations(ctx, existingConfirmations)
	if err != nil {
		return nil, err
	}

	// Now we can start the reconciliation process
	return c.blockListener.reconcileConfirmationsForTransaction(ctx, txHash, existingConfirmations, targetConfirmationCount)
}

// reconcileConfirmationsForTransaction reconciles the confirmation queue for a transaction
func (bl *blockListener) reconcileConfirmationsForTransaction(ctx context.Context, txHash string, existingConfirmations []*ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationUpdateResult, error) {

	// Fetch the block containing the transaction then start the algorithm proper
	txBlockInfo, err := bl.getBlockInfoContainsTxHash(ctx, txHash)
	if err != nil {
		log.L(ctx).Errorf("Failed to fetch block info using tx hash %s: %v", txHash, err)
		return nil, err
	}

	if txBlockInfo == nil {
		log.L(ctx).Debugf("Transaction %s not found in any block", txHash)
		return nil, i18n.NewError(ctx, msgs.MsgTransactionNotFound, txHash)
	}
	return bl.buildConfirmationList(ctx, existingConfirmations, txBlockInfo, targetConfirmationCount)
}

func (bl *blockListener) buildConfirmationList(ctx context.Context, existingConfirmations []*ffcapi.MinimalBlockInfo, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (*ffcapi.ConfirmationUpdateResult, error) {
	// Primary objective of this algorithm is to build a contiguous, linked list of `MinimalBlockInfo` structs, starting from the transaction block and ending as far as our current knowledge of the canonical chain allows.
	// Secondary objective is to report whether any fork was detected (and corrected) during this analysis
	// Initialize the result with existing confirmations
	reconcileResult := &ffcapi.ConfirmationUpdateResult{
		TargetConfirmationCount: targetConfirmationCount,
	}

	// before we get into the main algorithm, a couple of special cases to optimize for that can save us some work
	reconcileResult, err := bl.handleSpecialCases(ctx, existingConfirmations, txBlockInfo, targetConfirmationCount, reconcileResult)
	if reconcileResult.Confirmed || err != nil {
		return reconcileResult, err
	}

	// We start by constructing 2 lists of blocks:
	// - The `earlyList`.  This is the set of earliest blocks we are interested in.  At the least, it starts with the transaction block
	//    and may also contain some number of existing confirmations i.e. the output from previous call to this function
	//    Other than the `transactionBlock`, we don't yet know whether any of the early list is still correct as per the current state of the canonical chain.
	//    The chain may have been re-organized since we discovered the blocks in that list.
	// - The `lateList`. This is the most recent set of blocks that we are interesting in and we believe are accurate for the current state of the chain

	earlyList := createEarlyList(ctx, existingConfirmations, txBlockInfo, reconcileResult)
	lateList, err := createLateList(ctx, txBlockInfo, targetConfirmationCount, reconcileResult, bl)
	if err != nil {
		return nil, err
	}

	// These 2 lists may overlap so we splice them together which will remove any overlapping blocks
	splicedList, detectedFork := newSplice(earlyList, lateList)
	if detectedFork {
		reconcileResult.NewFork = true
	}
	for {
		// now loop until we can form a contiguous linked list from the spliced list

		if !splicedList.containsTransactionBlock() {
			// It contained the transaction when we first spliced the lists together
			// so it must have gotten removed because of a broken link
			// if this happens, it must mean that the chain is currently unstable and we need to start over
			reconcileResult.NewFork = true
			break
		}

		// inner loop to fill any gaps
		for splicedList.hasGap() {
			err = splicedList.fillGap(ctx, bl)
			if err != nil {
				return nil, err
			}
		}

		confirmations := splicedList.toSingleLinkedList()
		if confirmations != nil {
			// we have a contiguous list that starts with the transaction block and ends with the last block in the canonical chain
			// so we can return the result
			reconcileResult.Confirmations = confirmations
			break
		}

		// we filled all gaps and still cannot link the 2 lists, must be a fork.  Create a gap of one and try again
		reconcileResult.NewFork = true
		splicedList.removeBrokenLink()
	}

	reconcileResult.Confirmed = uint64(len(reconcileResult.Confirmations)) > targetConfirmationCount // do this maths here as a utility so that the consumer doesn't have to do it

	return reconcileResult, nil
}

// splice is the data structure that brings together 2 lists of block info with functions to remove redundant overlaps, to fill gaps and to validate linkability of the 2 lists
type splice struct {
	earlyList []*ffcapi.MinimalBlockInfo // beginning of the early list is the earliest block that we are interested in
	lateList  []*ffcapi.MinimalBlockInfo // late list is assumed to be the most recent view of the network's canonical chain
}

func newSplice(earlyList []*ffcapi.MinimalBlockInfo, lateList []*ffcapi.MinimalBlockInfo) (*splice, bool) {
	// remove any redundant overlaps between the 2 lists
	// for now, we are simply looking at block numbers to see if there is any block number for which both lists have a block info
	// if there is, we prefer to keep the block info from the late list because in the event that the 2 lists diverge, then the divergence point will be somewhere in the early list ( because we fetched the late list more recently)
	// and we will have fewer links to validate if we trim the overlap from the early list
	s := &splice{
		earlyList: earlyList,
		lateList:  lateList,
	}
	if len(s.earlyList) == 0 || len(s.lateList) == 0 {
		return s, false
	}
	detectedFork := false
	// if the early list is bigger than the gap between the transaction block number and the first block in the late list, then we have an overlap
	txBlockNumber := s.earlyList[0].BlockNumber.Uint64()
	firstLateBlockNumber := s.lateList[0].BlockNumber.Uint64()
	if uint64(len(s.earlyList))+txBlockNumber > firstLateBlockNumber {

		// there is an overlap so we need to discard the end of the early list but before we do, lets check whether it is equivalent to the equivalent blocks from the late
		// list so that we can report whether or not a fork was detected
		discardedEarlyListBlocks := s.earlyList[firstLateBlockNumber-txBlockNumber:]
		for i := range discardedEarlyListBlocks {
			if !discardedEarlyListBlocks[i].Equal(s.lateList[i]) {
				detectedFork = true
				break
			}
		}

		s.earlyList = s.earlyList[:firstLateBlockNumber-txBlockNumber]
	}
	return s, detectedFork
}

func (s *splice) hasGap() bool {
	return len(s.earlyList) > 0 &&
		len(s.lateList) > 0 &&
		s.earlyList[len(s.earlyList)-1].BlockNumber.Uint64()+1 < s.lateList[0].BlockNumber.Uint64()
}

func (s *splice) containsTransactionBlock() bool {
	// we haven't removed the first block from the early list
	return len(s.earlyList) > 0
}

func (s *splice) fillGap(ctx context.Context, blockListener *blockListener) error {
	if !s.hasGap() {
		// no gap to fill
		return nil
	}

	// fill one slot in the gap between the late list and the early list
	// always fill from the end of the gap ( i.e. the block before the start of the late list) because
	// the late list is our best view of the current canonical chain so working backwards from there will increase the number of blocks that we have a high confidence in

	freshBlockInfo, _, err := blockListener.getBlockInfoByNumber(ctx, s.lateList[0].BlockNumber.Uint64()-1, false, "", "")
	if err != nil {
		return err
	}
	if freshBlockInfo == nil {
		return i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	fetchedBlock := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(freshBlockInfo.Number.BigInt().Uint64()),
		BlockHash:   freshBlockInfo.Hash.String(),
		ParentHash:  freshBlockInfo.ParentHash.String(),
	}

	// Validate parent-child relationship
	if !fetchedBlock.IsParentOf(s.lateList[0]) {
		// most likely explanation of this is an unstable chain
		return i18n.NewError(ctx, msgs.MsgFailedToBuildConfirmationQueue)
	}

	// Prepend fetched block to confirmation queue
	s.lateList = append([]*ffcapi.MinimalBlockInfo{fetchedBlock}, s.lateList...)
	return nil
}

func (s *splice) removeBrokenLink() {
	if s.hasGap() {
		// nothing to remove if there is a gap
		return
	}
	// remove the last block from the early list because it is not the parent of the first block in the late list and we have higher confidence in the late list
	s.earlyList = s.earlyList[:len(s.earlyList)-1]

}

func (s *splice) toSingleLinkedList() []*ffcapi.MinimalBlockInfo {
	if s.hasGap() {
		return nil
	}
	if len(s.earlyList) == 0 {
		return s.lateList
	}
	if len(s.lateList) == 0 {
		return s.earlyList
	}
	if s.earlyList[len(s.earlyList)-1].IsParentOf(s.lateList[0]) {
		return append(s.earlyList, s.lateList...)
	}
	// cannot be linked because the last block in the early list is not the parent of the first block in the late list
	return nil

}

func createEarlyList(ctx context.Context, existingConfirmations []*ffcapi.MinimalBlockInfo, txBlockInfo *ffcapi.MinimalBlockInfo, reconcileResult *ffcapi.ConfirmationUpdateResult) (earlyList []*ffcapi.MinimalBlockInfo) {
	if len(existingConfirmations) > 0 && !existingConfirmations[0].Equal(txBlockInfo) {
		// otherwise we discard the existing confirmations queue
		reconcileResult.NewFork = true
	} else {
		earlyList = existingConfirmations
	}

	if len(existingConfirmations) == 0 {
		// either because this is the first time we are reconciling this transaction or because we just discarded the existing confirmations queue
		earlyList = []*ffcapi.MinimalBlockInfo{txBlockInfo}
	}
	return earlyList
}

func createLateList(ctx context.Context, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64, reconcileResult *ffcapi.ConfirmationUpdateResult, blockListener *blockListener) (lateList []*ffcapi.MinimalBlockInfo, err error) {
	lateList, err = blockListener.buildConfirmationQueueUsingInMemoryPartialChain(ctx, txBlockInfo, targetConfirmationCount)
	if err != nil {
		return nil, err
	}

	// If the late list is empty, it may be because the chain has moved on so far and the transaction is so old that
	// we no longer have the target block in memory. Lets try to grab the target block from the blockchain and work backwards from there.
	if len(lateList) == 0 {
		targetBlockInfo, _, err := blockListener.getBlockInfoByNumber(ctx, txBlockInfo.BlockNumber.Uint64()+targetConfirmationCount, false, "", "")
		if err != nil {
			return nil, err
		}
		if targetBlockInfo == nil {
			return nil, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
		}

		lateList = []*ffcapi.MinimalBlockInfo{
			{
				BlockNumber: fftypes.FFuint64(targetBlockInfo.Number.BigInt().Uint64()),
				BlockHash:   targetBlockInfo.Hash.String(),
				ParentHash:  targetBlockInfo.ParentHash.String(),
			},
		}
	}
	return lateList, nil
}

// buildConfirmationQueueUsingInMemoryPartialChain builds the confirmation queue using the in-memory partial chain.
// It does not modify the in-memory partial chain itself, only reads from it.
// This function holds a read lock on the in-memory partial chain, so it should not make long-running queries.
func (bl *blockListener) buildConfirmationQueueUsingInMemoryPartialChain(ctx context.Context, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64) (newConfirmationsWithoutTxBlock []*ffcapi.MinimalBlockInfo, err error) {
	bl.mux.RLock()
	defer bl.mux.RUnlock()
	txBlockNumber := txBlockInfo.BlockNumber.Uint64()
	targetBlockNumber := txBlockInfo.BlockNumber.Uint64() + targetConfirmationCount

	// Check if the in-memory partial chain has caught up to the transaction block
	chainTail := bl.canonicalChain.Back().Value.(*ffcapi.MinimalBlockInfo)
	if chainTail == nil || chainTail.BlockNumber.Uint64() < txBlockNumber {
		log.L(ctx).Debugf("in-memory partial chain is waiting for the transaction block %d to be indexed", txBlockNumber)
		return nil, i18n.NewError(ctx, msgs.MsgInMemoryPartialChainNotCaughtUp, txBlockNumber, txBlockInfo.BlockHash)
	}

	// Build new confirmations from blocks after the transaction block

	newConfirmationsWithoutTxBlock = []*ffcapi.MinimalBlockInfo{}
	nextInMemoryBlock := bl.canonicalChain.Front()
	for nextInMemoryBlock != nil {
		nextInMemoryBlockInfo := nextInMemoryBlock.Value.(*ffcapi.MinimalBlockInfo)

		// If we've reached the target confirmation count, mark as confirmed
		if nextInMemoryBlockInfo.BlockNumber.Uint64() > targetBlockNumber {
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
	return newConfirmationsWithoutTxBlock, nil
}

func (bl *blockListener) getBlockByNumberFromInMemoryPartialChain(ctx context.Context, blockNumber uint64) *ffcapi.MinimalBlockInfo {
	bl.mux.RLock()
	defer bl.mux.RUnlock()
	if blockNumber < bl.canonicalChain.Front().Value.(*ffcapi.MinimalBlockInfo).BlockNumber.Uint64() {
		return nil
	}
	if blockNumber > bl.canonicalChain.Back().Value.(*ffcapi.MinimalBlockInfo).BlockNumber.Uint64() {
		return nil
	}
	for nextInMemoryBlock := bl.canonicalChain.Front(); nextInMemoryBlock != nil; nextInMemoryBlock = nextInMemoryBlock.Next() {
		nextInMemoryBlockInfo := nextInMemoryBlock.Value.(*ffcapi.MinimalBlockInfo)
		if nextInMemoryBlockInfo.BlockNumber.Uint64() == blockNumber {
			return nextInMemoryBlockInfo
		}
	}
	return nil
}

func validateExistingConfirmations(ctx context.Context, existingConfirmations []*ffcapi.MinimalBlockInfo) error {
	var previousBlock *ffcapi.MinimalBlockInfo
	var previousBlockNumber uint64
	for _, existingConfirmation := range existingConfirmations {
		if previousBlock != nil {
			if existingConfirmation.BlockNumber.Uint64() != previousBlockNumber+1 {
				return i18n.NewError(ctx, msgs.MsgFailedToBuildConfirmationQueue)
			}
			if !previousBlock.IsParentOf(existingConfirmation) {
				return i18n.NewError(ctx, msgs.MsgFailedToBuildConfirmationQueue)
			}
		}
		previousBlock = existingConfirmation
		previousBlockNumber = existingConfirmation.BlockNumber.Uint64()

	}
	return nil
}

func (bl *blockListener) handleSpecialCases(ctx context.Context, existingConfirmations []*ffcapi.MinimalBlockInfo, txBlockInfo *ffcapi.MinimalBlockInfo, targetConfirmationCount uint64, reconcileResult *ffcapi.ConfirmationUpdateResult) (*ffcapi.ConfirmationUpdateResult, error) {
	if targetConfirmationCount == 0 {
		// if the target confirmation count is 0, we can immediately return a confirmed result
		reconcileResult.Confirmed = true
		reconcileResult.Confirmations = []*ffcapi.MinimalBlockInfo{txBlockInfo}
		return reconcileResult, nil
	}

	if uint64(len(existingConfirmations)) > targetConfirmationCount {
		if existingConfirmations[0].Equal(txBlockInfo) {
			// start of the existing confirmations  aligns with our latest view of the chain

			// attempt to validate the rest of the existing confirmations.  Starting with the target confirmation block and working forwards

			attemptIndex := targetConfirmationCount

			for attemptIndex < uint64(len(existingConfirmations))-1 {
				existingConfirmationToValidate := existingConfirmations[attemptIndex]
				blockInfo := bl.getBlockByNumberFromInMemoryPartialChain(ctx, existingConfirmationToValidate.BlockNumber.Uint64())
				if blockInfo == nil {
					attemptIndex++
					continue
				}
				if blockInfo.BlockHash == existingConfirmationToValidate.BlockHash {
					// the last block in the existing confirmations queue is still valid
					reconcileResult.Confirmed = true
					reconcileResult.Confirmations = existingConfirmations[:targetConfirmationCount+1]
					return reconcileResult, nil
				}
			}

			// if we didn't get a conclusive answer from the in memory cache of the chain, we need to fetch the block from the blockchain
			targetBlock := existingConfirmations[targetConfirmationCount]
			blockInfo, _, err := bl.getBlockInfoByNumber(ctx, targetBlock.BlockNumber.Uint64(), false, "", "")
			if err != nil {
				return nil, err
			}

			if blockInfo.Hash.String() == targetBlock.BlockHash {
				reconcileResult.Confirmed = true
				reconcileResult.Confirmations = existingConfirmations[:targetConfirmationCount+1]
				return reconcileResult, nil
			}
		}
	}
	return reconcileResult, nil
}
