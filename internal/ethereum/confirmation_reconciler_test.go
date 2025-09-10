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
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/apitypes"
	"github.com/stretchr/testify/assert"
)

func TestCompareAndUpdateConfirmationQueue_EmptyChain(t *testing.T) {
	// Setup - create a chain with one block that's older than the transaction
	bl := &blockListener{
		canonicalChain: createTestChain(50, 50), // Single block at 50, tx is at 100
	}
	ctx := context.Background()
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"

	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

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
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"

	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

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
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: nil,
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.NotNil(t, occ.ConfirmationMap)
	assert.True(t, occ.HasNewFork)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.Equal(t, txBlockHash, occ.ConfirmationMap.CanonicalBlockHash)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_NilConfirmationMapUnconfirmed(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 104),
	}
	ctx := context.Background()
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: nil,
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.NotNil(t, occ.ConfirmationMap)
	assert.True(t, occ.HasNewFork)
	assert.True(t, occ.HasNewConfirmation)
	assert.False(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.Equal(t, txBlockHash, occ.ConfirmationMap.CanonicalBlockHash)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 5)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_EmptyConfirmationQueue(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: make(map[string][]*apitypes.Confirmation),
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.True(t, occ.HasNewFork)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.Equal(t, txBlockHash, occ.ConfirmationMap.CanonicalBlockHash)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

// theoretically, this should never happen because block hash generation has block number as part of the input
func TestCompareAndUpdateConfirmationQueue_DifferentBlockNumber(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(99), ParentHash: "0xblock99"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.True(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	// The code builds a full confirmation queue from the canonical chain
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_ExistingConfirmationsTooDistant(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(145, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

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
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, bl.canonicalChain.Front().Value.(*minimalBlockInfo).number, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_CorruptedExistingConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	// Create corrupted confirmation (wrong parent hash)
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xwrongparent"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, "0xblock100", occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].ParentHash)
}

func TestCompareAndUpdateConfirmationQueue_ConnectionNodeMismatch(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(102, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblockwrong", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
		{BlockHash: "0xblock103", BlockNumber: fftypes.FFuint64(103), ParentHash: "0xblock102"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 5)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, "0xblock102", occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockHash)
	assert.Equal(t, "0xblock102", occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].ParentHash)
}

func TestCompareAndUpdateConfirmationQueue_CorruptedExistingConfirmationAfterFirstConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblockwrong"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 5)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, "0xblock102", occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockHash)
	assert.Equal(t, "0xblock102", occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].ParentHash)
}

func TestCompareAndUpdateConfirmationQueue_NewForkAfterFirstConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "fork1", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.True(t, occ.HasNewFork)
	assert.False(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
}

func TestCompareAndUpdateConfirmationQueue_NewFork(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "fork1", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "fork2", BlockNumber: fftypes.FFuint64(102), ParentHash: "fork1"},
		{BlockHash: "fork3", BlockNumber: fftypes.FFuint64(103), ParentHash: "fork2"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 4)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+4, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+5, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_ExistingConfirmationLaterThanCurrentBlock(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(100, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock103", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_AlreadyConfirmable(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	// Create confirmations that already meet the target
	// and it connects to the canonical chain to validate they are still valid
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
		{BlockHash: "0xblock103", BlockNumber: fftypes.FFuint64(103), ParentHash: "0xblock102"},

		// all blocks after the first block of the canonical chain are discarded in the final confirmation queue
		{BlockHash: "0xblock104", BlockNumber: fftypes.FFuint64(104), ParentHash: "0xblock103"}, // discarded
		{BlockHash: "0xblock105", BlockNumber: fftypes.FFuint64(105), ParentHash: "0xblock104"}, // discarded
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 2

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	// The confirmation queue should return the confirmation queue up to the first block of the canonical chain

	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.HasNewConfirmation)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 4)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_AlreadyConfirmableConnectable(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(103, 150),
	}
	ctx := context.Background()
	// Create confirmations that already meet the target
	// and it connects to the canonical chain to validate they are still valid
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
		// didn't have block 103, which is the first block of the canonical chain
		// but we should still be able to validate the existing confirmations are valid using parent hash
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 1

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	// The confirmation queue should return the confirmation queue up to the first block of the canonical chain

	assert.True(t, occ.Confirmed)
	assert.False(t, occ.Rebuilt)
	assert.False(t, occ.HasNewFork)
	assert.False(t, occ.HasNewConfirmation)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 4)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_HasSufficientConfirmationsButNoOverlapWithCanonicalChain(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(104, 150),
	}
	ctx := context.Background()
	// Create confirmations that already meet the target
	// and it connects to the canonical chain to validate they are still valid
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 1

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
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, int64(104), int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))

}

func TestCompareAndUpdateConfirmationQueue_ValidExistingConfirmations(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

	// Execute
	bl.compareAndUpdateConfirmationQueue(ctx, occ, txBlockInfo, targetConfirmationCount)

	// Assert
	assert.False(t, occ.HasNewFork)
	assert.True(t, occ.Rebuilt)
	assert.True(t, occ.HasNewConfirmation)
	assert.True(t, occ.Confirmed)
	assert.Len(t, occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash], 6)
	assert.Equal(t, txBlockNumber, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][0].BlockNumber))
	assert.Equal(t, txBlockNumber+1, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][1].BlockNumber))
	assert.Equal(t, txBlockNumber+2, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][2].BlockNumber))
	assert.Equal(t, txBlockNumber+3, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][3].BlockNumber))
	assert.Equal(t, txBlockNumber+4, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][4].BlockNumber))
	assert.Equal(t, txBlockNumber+5, int64(occ.ConfirmationMap.ConfirmationQueueMap[txBlockHash][5].BlockNumber))
}

func TestCompareAndUpdateConfirmationQueue_ReachTargetConfirmation(t *testing.T) {
	// Setup
	bl := &blockListener{
		canonicalChain: createTestChain(50, 150),
	}
	ctx := context.Background()
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: make(map[string][]*apitypes.Confirmation),
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 3

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
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		// no block 101, which is the first block of the canonical chain
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(102), ParentHash: "0xblock101"},
		{BlockHash: "0xblock103", BlockNumber: fftypes.FFuint64(103), ParentHash: "0xblock102"},
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

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
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(99), ParentHash: "0xblock100"}, // somehow there is a lower block number
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

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
	existingQueue := []*apitypes.Confirmation{
		{BlockHash: "0xblock100", BlockNumber: fftypes.FFuint64(100), ParentHash: "0xblock99"},
		{BlockHash: "0xblock101", BlockNumber: fftypes.FFuint64(101), ParentHash: "0xblock100"},
		{BlockHash: "0xblock102", BlockNumber: fftypes.FFuint64(99), ParentHash: "0xblock101"}, // somehow there is a lower block number
	}
	occ := &ConfirmationMapUpdateResult{
		ConfirmationMap: &ConfirmationMap{
			ConfirmationQueueMap: map[string][]*apitypes.Confirmation{
				"0xblock100": existingQueue,
			},
		},
	}
	txBlockNumber := int64(100)
	txBlockHash := "0xblock100"
	txBlockInfo := &minimalBlockInfo{
		number:     txBlockNumber,
		hash:       txBlockHash,
		parentHash: "0xblock99",
	}
	targetConfirmationCount := 5

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

func createTestChain(startBlock, endBlock int64) *list.List {
	chain := list.New()
	for i := startBlock; i <= endBlock; i++ {
		blockInfo := &minimalBlockInfo{
			number:     i,
			hash:       fmt.Sprintf("0xblock%d", i),
			parentHash: fmt.Sprintf("0xblock%d", i-1),
		}
		chain.PushBack(blockInfo)
	}
	return chain
}
