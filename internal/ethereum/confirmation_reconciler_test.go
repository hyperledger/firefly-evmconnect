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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Tests of the reconcileConfirmationsForTransaction function

func TestReconcileConfirmationsForTransaction_TransactionNotFound(t *testing.T) {

	_, c, mRPC, _ := newTestConnectorWithNoBlockerFilterDefaultMocks(t)

	// Mock for TransactionReceipt call - return nil to simulate transaction not found
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt", generateTestHash(100)).Return(nil).Run(func(args mock.Arguments) {
		err := json.Unmarshal([]byte("null"), args[1])
		assert.NoError(t, err)
	})

	// Execute the reconcileConfirmationsForTransaction function
	result, err := c.ReconcileConfirmationsForTransaction(context.Background(), generateTestHash(100), nil, 5)

	// Assertions - expect an error when transaction doesn't exist
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasNewFork)
	assert.False(t, result.Rebuilt)
	assert.False(t, result.HasNewConfirmation)
	assert.False(t, result.Confirmed)
	assert.Nil(t, result.ConfirmationMap)
	assert.Equal(t, uint64(5), result.TargetConfirmationCount)

	mRPC.AssertExpectations(t)
}

func TestReconcileConfirmationsForTransaction_ReceiptRPCCallError(t *testing.T) {

	_, c, mRPC, _ := newTestConnectorWithNoBlockerFilterDefaultMocks(t)

	// Mock for TransactionReceipt call - return error to simulate RPC call error
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt", generateTestHash(100)).Return(&rpcbackend.RPCError{Message: "pop"}).Run(func(args mock.Arguments) {
		err := json.Unmarshal([]byte("null"), args[1])
		assert.NoError(t, err)
	})

	// Execute the reconcileConfirmationsForTransaction function
	result, err := c.ReconcileConfirmationsForTransaction(context.Background(), generateTestHash(100), &ffcapi.ConfirmationMap{}, 5)

	// Assertions - expect an error when RPC call fails
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestReconcileConfirmationsForTransaction_BlockNotFound(t *testing.T) {

	_, c, mRPC, _ := newTestConnectorWithNoBlockerFilterDefaultMocks(t)

	// Mock for TransactionReceipt call
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceipt), args[1])
			assert.NoError(t, err)
		})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().String() == "1977"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		err := json.Unmarshal([]byte("null"), args[1])
		assert.NoError(t, err)
	})

	// Execute the reconcileConfirmationsForTransaction function
	result, err := c.ReconcileConfirmationsForTransaction(context.Background(), "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", &ffcapi.ConfirmationMap{
		ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
			generateTestHash(1977): {
				{BlockNumber: fftypes.FFuint64(1977), BlockHash: generateTestHash(1977), ParentHash: generateTestHash(1976)},
			},
		},
	}, 5)

	// Assertions - expect an error when transaction doesn't exist
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasNewFork)
	assert.False(t, result.Rebuilt)
	assert.False(t, result.HasNewConfirmation)
	assert.False(t, result.Confirmed)
	assert.Equal(t, &ffcapi.ConfirmationMap{
		ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
			generateTestHash(1977): {
				{BlockNumber: fftypes.FFuint64(1977), BlockHash: generateTestHash(1977), ParentHash: generateTestHash(1976)},
			},
		},
	}, result.ConfirmationMap)
	assert.Equal(t, uint64(5), result.TargetConfirmationCount)

	mRPC.AssertExpectations(t)
}

func TestReconcileConfirmationsForTransaction_BlockRPCCallError(t *testing.T) {

	_, c, mRPC, _ := newTestConnectorWithNoBlockerFilterDefaultMocks(t)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceipt), args[1])
			assert.NoError(t, err)
		})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().String() == "1977"
	}), false).Return(&rpcbackend.RPCError{Message: "pop"})

	// Execute the reconcileConfirmationsForTransaction function
	result, err := c.ReconcileConfirmationsForTransaction(context.Background(), "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", &ffcapi.ConfirmationMap{}, 5)

	// Assertions - expect an error when RPC call fails
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestReconcileConfirmationsForTransaction_TxBlockNotInCanonicalChain(t *testing.T) {

	_, c, mRPC, _ := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.canonicalChain = createTestChain(1976, 1978) // Single block at 50, tx is at 100

	// Mock for TransactionReceipt call
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceipt), args[1])
			assert.NoError(t, err)
		})

	fakeParentHash := fftypes.NewRandB32().String()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().String() == "1977"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1977),
			Hash:       ethtypes.MustNewHexBytes0xPrefix(generateTestHash(1977)),
			ParentHash: ethtypes.MustNewHexBytes0xPrefix(fakeParentHash),
		}
	})

	// Execute the reconcileConfirmationsForTransaction function
	result, err := c.ReconcileConfirmationsForTransaction(context.Background(), "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", &ffcapi.ConfirmationMap{
		ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
			generateTestHash(1977): {},
		},
	}, 5)

	// Assertions - expect the existing confirmation queue to be returned because the tx block doesn't match the same block number in the canonical chain
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasNewFork)
	assert.False(t, result.Rebuilt)
	assert.False(t, result.HasNewConfirmation)
	assert.False(t, result.Confirmed)
	assert.Equal(t, &ffcapi.ConfirmationMap{
		ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
			generateTestHash(1977): {},
		},
	}, result.ConfirmationMap)
	assert.Equal(t, uint64(5), result.TargetConfirmationCount)

	mRPC.AssertExpectations(t)
}

func TestReconcileConfirmationsForTransaction_NewConfirmation(t *testing.T) {

	_, c, mRPC, _ := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.canonicalChain = createTestChain(1976, 1978) // Single block at 50, tx is at 100

	// Mock for TransactionReceipt call
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionReceipt",
		mock.MatchedBy(func(txHash string) bool {
			assert.Equal(t, "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", txHash)
			return true
		})).
		Return(nil).
		Run(func(args mock.Arguments) {
			err := json.Unmarshal([]byte(sampleJSONRPCReceipt), args[1])
			assert.NoError(t, err)
		})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().String() == "1977"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1977),
			Hash:       ethtypes.MustNewHexBytes0xPrefix(generateTestHash(1977)),
			ParentHash: ethtypes.MustNewHexBytes0xPrefix(generateTestHash(1976)),
		}
	})

	// Execute the reconcileConfirmationsForTransaction function
	result, err := c.ReconcileConfirmationsForTransaction(context.Background(), "0x6197ef1a58a2a592bb447efb651f0db7945de21aa8048801b250bd7b7431f9b6", &ffcapi.ConfirmationMap{
		ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
			generateTestHash(1977): {},
		},
	}, 5)

	// Assertions - expect the existing confirmation queue to be returned because the tx block doesn't match the same block number in the canonical chain
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasNewFork)
	assert.False(t, result.Rebuilt)
	assert.True(t, result.HasNewConfirmation)
	assert.False(t, result.Confirmed)
	assert.Equal(t, &ffcapi.ConfirmationMap{
		ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
			generateTestHash(1977): {
				{BlockNumber: fftypes.FFuint64(1977), BlockHash: generateTestHash(1977), ParentHash: generateTestHash(1976)},
				{BlockNumber: fftypes.FFuint64(1978), BlockHash: generateTestHash(1978), ParentHash: generateTestHash(1977)},
			},
		},
		CanonicalBlockHash: generateTestHash(1977),
	}, result.ConfirmationMap)
	assert.Equal(t, uint64(5), result.TargetConfirmationCount)

	mRPC.AssertExpectations(t)
}

// Tests of the compareAndUpdateConfirmationQueue function

func TestCompareAndUpdateConfirmationQueue_EmptyChain(t *testing.T) {
	// Setup - create a chain with one block that's older than the transaction
	bl := &blockListener{
		canonicalChain: createTestChain(50, 50), // Single block at 50, tx is at 100
	}
	ctx := context.Background()
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(txBlockNumber)

	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(txBlockNumber - 1),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert - should return early due to chain being too short
	assert.NotNil(t, occ.ConfirmationMap)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 0)
	assert.NotNil(t, occ.ConfirmationMap)
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.HasNewConfirmation)
	assert.False(t, occ.Rebuilt)
	assert.False(t, occ.Confirmed)
}

func TestCompareAndUpdateConfirmationQueue_ChainTooShort(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 99), // Chain ends at 99, tx is at 100
	}
	ctx := context.Background()
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(txBlockNumber)

	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(txBlockNumber - 1),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert - should return early due to chain being too short
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 0)
	assert.NotNil(t, occ.ConfirmationMap)
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.HasNewConfirmation)
	assert.False(t, occ.Rebuilt)
	assert.False(t, occ.Confirmed)
}

func TestCompareAndUpdateConfirmationQueue_NilConfirmationMap(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: nil,
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(txBlockNumber)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(txBlockNumber - 1),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.NotNil(t, occ.ConfirmationMap)
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.Equal(t, txBlockHash, occ.ConfirmationMap.CanonicalBlockHash)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_NilConfirmationMapUnconfirmed(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 104),
	}
	ctx := context.Background()
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: nil,
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(txBlockNumber)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(txBlockNumber - 1),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.NotNil(t, occ.ConfirmationMap)
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.HasNewConfirmation)
	assert.False(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.Equal(t, txBlockHash, occ.ConfirmationMap.CanonicalBlockHash)
	// The code builds a confirmation queue from the canonical chain up to the available blocks
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 5) // 100, 101, 102, 103, 104
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_EmptyConfirmationQueue(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: make(map[string][]*ffcapi.MinimalBlockInfo),
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(txBlockNumber)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(txBlockNumber - 1),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.Equal(t, txBlockHash, occ.ConfirmationMap.CanonicalBlockHash)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

// theoretically, this should never happen because block hash generation has block number as part of the input
func TestCompareAndUpdateConfirmationQueue_DifferentBlockNumber(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(99), ParentHash: generateTestHash(98)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(txBlockNumber)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(txBlockNumber - 1),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.True(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_MismatchConfirmationBlock(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(101)}, // wrong parent hash, so the existing queue should be discarded
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
		{BlockHash: generateTestHash(103), BlockNumber: fftypes.FFuint64(103), ParentHash: generateTestHash(102)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 4)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_ExistingConfirmationsTooDistant(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(145, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	// only the tx block and the first block in the canonical chain are in the confirmation queue
	// and the transaction is confirmed
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 2)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, bl.canonicalChain.Front().Value.(*ffcapi.MinimalBlockInfo).BlockNumber, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber)
}

func TestCompareAndUpdateConfirmationQueue_CorruptedExistingConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	// Create corrupted confirmation (wrong parent hash)
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: "0xwrongparent"},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, generateTestHash(100), occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].ParentHash)
}

func TestCompareAndUpdateConfirmationQueue_ConnectionNodeMismatch(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(102, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: "0xblockwrong", BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
		{BlockHash: generateTestHash(103), BlockNumber: fftypes.FFuint64(103), ParentHash: generateTestHash(102)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 5)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, generateTestHash(102), occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockHash)
	assert.Equal(t, generateTestHash(102), occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].ParentHash)
}

func TestCompareAndUpdateConfirmationQueue_CorruptedExistingConfirmationAfterFirstConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblockwrong"},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 5)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, generateTestHash(102), occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockHash)
	assert.Equal(t, generateTestHash(102), occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].ParentHash)
}

func TestCompareAndUpdateConfirmationQueue_NewForkAfterFirstConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: "fork1", BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.True(t, occ.HasNewFork)
	assert.False(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
}

func TestCompareAndUpdateConfirmationQueue_NewForkAndNoConnectionToCanonicalChain(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: "fork1", BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: "fork2", BlockNumber: fftypes.FFuint64(102), ParentHash: "fork1"},
		{BlockHash: "fork3", BlockNumber: fftypes.FFuint64(103), ParentHash: "fork2"},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 4)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_ExistingConfirmationLaterThanCurrentBlock(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(103), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_AlreadyConfirmable(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	// Create confirmations that already meet the target
	// and it connects to the canonical chain to validate they are still valid
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
		{BlockHash: generateTestHash(103), BlockNumber: fftypes.FFuint64(103), ParentHash: generateTestHash(102)},

		// all blocks after the first block of the canonical chain are discarded in the final confirmation queue
		{BlockHash: "0xblock104", BlockNumber: fftypes.FFuint64(104), ParentHash: generateTestHash(103)}, // discarded
		{BlockHash: "0xblock105", BlockNumber: fftypes.FFuint64(105), ParentHash: "0xblock104"},          // discarded
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(2)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.HasNewConfirmation)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 3)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_AlreadyConfirmableConnectable(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	// Create confirmations that already meet the target
	// and it connects to the canonical chain to validate they are still valid
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
		// didn't have block 103, which is the first block of the canonical chain
		// but we should still be able to validate the existing confirmations are valid using parent hash
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(1)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	// The confirmation queue should return the confirmation queue up to the first block of the canonical chain

	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.HasNewConfirmation)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 2)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_AlreadyConfirmableButAllExistingConfirmationsAreTooHighForTargetConfirmationCount(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	// Create confirmations that already meet the target
	// and it connects to the canonical chain to validate they are still valid
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		// gap of 101 is allowed, and is the confirmation required for the transaction with target confirmation count of 1
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(1)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	// The confirmation queue should return the tx block and  the first block of the canonical chain

	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.HasNewConfirmation)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 2)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, uint64(103), uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_HasSufficientConfirmationsButNoOverlapWithCanonicalChain(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(104, 150),
	}
	ctx := context.Background()
	// Create confirmations that already meet the target
	// and it connects to the canonical chain to validate they are still valid
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(1)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	// Because the existing confirmations do not have overlap with the canonical chain,
	// the confirmation queue should return the tx block and the first block of the canonical chain
	assert.True(t, occ.Confirmed)
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 2)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, uint64(104), uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_ValidExistingConfirmations(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_ValidExistingTxBlock(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, uint64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_ReachTargetConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: make(map[string][]*ffcapi.MinimalBlockInfo),
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(3)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	// The code builds a full confirmation queue from the canonical chain
	assert.GreaterOrEqual(t, len(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash]), 4) // tx block + 3 confirmations
}

func TestCompareAndUpdateConfirmationQueue_ExistingConfirmationsWithGap(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(101, 150),
	}
	ctx := context.Background()
	// Create confirmations with a gap (missing block 102)
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		// no block 101, which is the first block of the canonical chain
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(102), ParentHash: generateTestHash(101)},
		{BlockHash: generateTestHash(103), BlockNumber: fftypes.FFuint64(103), ParentHash: generateTestHash(102)},
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
}

func TestCompareAndUpdateConfirmationQueue_ExistingConfirmationsWithLowerBlockNumber(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	// Create confirmations with a lower block number
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(99), ParentHash: generateTestHash(100)}, // somehow there is a lower block number
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
}

func TestCompareAndUpdateConfirmationQueue_ExistingConfirmationsWithLowerBlockNumberAfterFirstConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(101, 150),
	}
	ctx := context.Background()
	// Create confirmations with a lower block number
	existingQueue := []*ffcapi.MinimalBlockInfo{
		{BlockHash: generateTestHash(100), BlockNumber: fftypes.FFuint64(100), ParentHash: generateTestHash(99)},
		{BlockHash: generateTestHash(101), BlockNumber: fftypes.FFuint64(101), ParentHash: generateTestHash(100)},
		{BlockHash: generateTestHash(102), BlockNumber: fftypes.FFuint64(99), ParentHash: generateTestHash(101)}, // somehow there is a lower block number
	}
	occ := &ffcapi.ConfirmationMapUpdateResult{
		ConfirmationMap: &ffcapi.ConfirmationMap{
			ConfirmationQueueMap: map[string][]*ffcapi.MinimalBlockInfo{
				generateTestHash(100): existingQueue,
			},
		},
	}
	txBlockNumber := uint64(100)
	txBlockHash := generateTestHash(100)
	txBlockInfo := &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(txBlockNumber),
		BlockHash:   txBlockHash,
		ParentHash:  generateTestHash(99),
	}
	targetConfirmationCount := uint64(5)

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
}

// Helper functions

// generateTestHash creates a predictable hash for testing with consistent prefix and last 4 digits as index
func generateTestHash(index uint64) string {
	return fmt.Sprintf("0x%060x", index)
}

func createTestChain(startBlock, endBlock uint64) *list.List {
	chain := list.New()
	for i := startBlock; i <= endBlock; i++ {
		blockHash := generateTestHash(i)

		var parentHash string
		if i > startBlock || i > 0 {
			parentHash = generateTestHash(i - 1)
		} else {
			// For the first block, if it's 0, use a dummy parent hash
			parentHash = generateTestHash(9999) // Use a high number to avoid conflicts
		}

		blockInfo := &ffcapi.MinimalBlockInfo{
			BlockNumber: fftypes.FFuint64(i),
			BlockHash:   blockHash,
			ParentHash:  parentHash,
		}
		chain.PushBack(blockInfo)
	}
	return chain
}
