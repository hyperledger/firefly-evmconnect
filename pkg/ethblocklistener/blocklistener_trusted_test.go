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
	"context"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-evmconnect/mocks/rpcbackendmocks"
	"github.com/hyperledger/firefly-evmconnect/pkg/ethrpc"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestTrustedBlockListener(t *testing.T, confSetup ...func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc)) (context.Context, *blockListener, *rpcbackendmocks.Backend, func()) {
	return newTestBlockListener(t, append([]func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc){
		func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
			conf.Mode = BlockListenerModeTrusted
		},
	}, confSetup...)...)
}

func TestTrustedListenLoopOKSequential(t *testing.T) {
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	startLatch := newTestLatch()
	_, bl, mRPC, done := newTestTrustedBlockListener(t, func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
		conf.BlockPollingInterval = shortDelay

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*string)
			*hbh = testBlockFilterID1
		})
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
			startLatch.waitComplete()
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{block1001Hash, block1002Hash}
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1002)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{block1003Hash}
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1003)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1003)
		})
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.AddConsumer(context.Background(), &BlockUpdateConsumer{
		ID:      fftypes.NewUUID(),
		Ctx:     context.Background(),
		Updates: updates,
	})
	startLatch.complete()

	bu := <-updates
	assert.True(t, bu.GapPotential)
	assert.Equal(t, []string{block1001Hash.String(), block1002Hash.String()}, bu.BlockHashes)

	bu = <-updates
	assert.False(t, bu.GapPotential)
	assert.Equal(t, []string{block1003Hash.String()}, bu.BlockHashes)

	done()
	<-bl.listenLoopDone
	assert.Equal(t, uint64(1003), bl.highestBlock)
	assert.Empty(t, bl.SnapshotMonitoredHeadChain())
	mRPC.AssertExpectations(t)
}

func TestTrustedListenLoopNewBlockFilterFail(t *testing.T) {
	_, bl, mRPC, done := newTestTrustedBlockListener(t, func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
		conf.BlockPollingInterval = shortDelay

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").
			Return(&rpcbackend.RPCError{Message: "pop"}).
			Run(func(args mock.Arguments) {
				go cancelCtx()
			})
	})

	bl.checkAndStartListenerLoop()
	bl.WaitClosed()
	done()
	mRPC.AssertExpectations(t)
}

func TestTrustedListenLoopFilterChangesFailAndRecover(t *testing.T) {
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	waitForBlock := newTestLatch()
	_, bl, mRPC, done := newTestTrustedBlockListener(t, func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
		conf.BlockPollingInterval = shortDelay

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*string)
			*hbh = testBlockFilterID1
		})

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).
			Return(&rpcbackend.RPCError{Message: "server error"}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{block1001Hash}
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1001)
			waitForBlock.complete()
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1001)
		})
	})

	bl.checkAndStartListenerLoop()
	waitForBlock.waitComplete()
	assert.Equal(t, uint64(1001), bl.highestBlock)

	done()
	<-bl.listenLoopDone
	mRPC.AssertExpectations(t)
}

func TestTrustedListenLoopFilterNotFoundRecreate(t *testing.T) {
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	waitForBlock := newTestLatch()
	_, bl, mRPC, done := newTestTrustedBlockListener(t, func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
		conf.BlockPollingInterval = shortDelay

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*string)
			*hbh = testBlockFilterID1
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).
			Return(&rpcbackend.RPCError{Message: "filter not found"}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*string)
			*hbh = testBlockFilterID2
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID2).Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{block1001Hash}
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1001)
			waitForBlock.complete()
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1001)
		})
	})

	bl.checkAndStartListenerLoop()
	waitForBlock.waitComplete()
	assert.Equal(t, uint64(1001), bl.highestBlock)

	done()
	<-bl.listenLoopDone
	mRPC.AssertExpectations(t)
}

func TestTrustedListenLoopBlockNumberFail(t *testing.T) {
	waitRetried := newTestLatch()
	_, bl, mRPC, done := newTestTrustedBlockListener(t, func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
		conf.BlockPollingInterval = shortDelay

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*string)
			*hbh = testBlockFilterID1
		})
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil)

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").
			Return(&rpcbackend.RPCError{Message: "node down"}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1001)
			waitRetried.complete()
		})
	})

	bl.checkAndStartListenerLoop()
	waitRetried.waitComplete()
	assert.Equal(t, uint64(1001), bl.highestBlock)

	done()
	<-bl.listenLoopDone
	mRPC.AssertExpectations(t)
}

func TestTrustedListenLoopExitOnContextCancelDuringEstablish(t *testing.T) {
	_, bl, mRPC, done := newTestTrustedBlockListener(t)
	done()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").
		Return(&rpcbackend.RPCError{Message: "pop"}).Once()

	h, ok := bl.GetHighestBlock(bl.ctx)
	assert.False(t, ok)
	assert.Equal(t, uint64(0), h)

	<-bl.listenLoopDone
	mRPC.AssertExpectations(t)
}

func TestTrustedListenLoopEmptyFilterChanges(t *testing.T) {
	waitEmpty := newTestLatch()
	_, bl, mRPC, done := newTestTrustedBlockListener(t, func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
		conf.BlockPollingInterval = shortDelay

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*string)
			*hbh = testBlockFilterID1
		})

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
			// no hashes returned
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
			waitEmpty.complete()
		}).Once()

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		})
	})

	bl.checkAndStartListenerLoop()
	waitEmpty.waitComplete()

	done()
	<-bl.listenLoopDone
	assert.Equal(t, uint64(1000), bl.highestBlock)
	mRPC.AssertExpectations(t)
}

func TestTrustedListenLoopExitOnContextCancelDuringWait(t *testing.T) {
	_, bl, mRPC, done := newTestTrustedBlockListener(t, func(conf *BlockListenerConfig, mRPC *rpcbackendmocks.Backend, cancelCtx context.CancelFunc) {
		conf.BlockPollingInterval = 1 * time.Hour

		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*string)
			*hbh = testBlockFilterID1
		})
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
			go func() {
				time.Sleep(50 * time.Millisecond)
				cancelCtx()
			}()
		}).Once()
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
			hbh := args[1].(*ethtypes.HexInteger)
			*hbh = *ethtypes.NewHexIntegerU64(1000)
		})
	})

	bl.checkAndStartListenerLoop()
	<-bl.listenLoopDone
	done()
	mRPC.AssertExpectations(t)
}

// --- Guard tests for trusted mode ---

func TestTrustedModeGuardGetBlockInfoByNumber(t *testing.T) {
	ctx, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	_, err := bl.GetBlockInfoByNumber(ctx, 1000, false, "", "")
	require.Regexp(t, "FF23069", err)
}

func TestTrustedModeGuardGetBlockInfoByHash(t *testing.T) {
	ctx, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	_, err := bl.GetBlockInfoByHash(ctx, "0xabc")
	require.Regexp(t, "FF23069", err)
}

func TestTrustedModeGuardGetEVMBlockWithTxHashesByHash(t *testing.T) {
	ctx, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	_, err := bl.GetEVMBlockWithTxHashesByHash(ctx, "0xabc")
	require.Regexp(t, "FF23069", err)
}

func TestTrustedModeGuardGetEVMBlockWithTransactionsByHash(t *testing.T) {
	ctx, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	_, err := bl.GetEVMBlockWithTransactionsByHash(ctx, "0xabc")
	require.Regexp(t, "FF23069", err)
}

func TestTrustedModeGuardGetEVMBlockWithTxHashesByNumber(t *testing.T) {
	ctx, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	_, err := bl.GetEVMBlockWithTxHashesByNumber(ctx, "0x1")
	require.Regexp(t, "FF23069", err)
}

func TestTrustedModeGuardGetEVMBlockWithTransactionsByNumber(t *testing.T) {
	ctx, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	_, err := bl.GetEVMBlockWithTransactionsByNumber(ctx, "0x1")
	require.Regexp(t, "FF23069", err)
}

func TestTrustedModeGuardReconcileConfirmationsForTransaction(t *testing.T) {
	ctx, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	_, _, err := bl.ReconcileConfirmationsForTransaction(ctx, "0xabc", nil, 10)
	require.Regexp(t, "FF23069", err)
}

func TestTrustedModeGuardFetchBlockReceiptsAsync(t *testing.T) {
	_, bl, _, done := newTestTrustedBlockListener(t)
	defer done()

	blockHash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	fetched := make(chan struct{})
	bl.FetchBlockReceiptsAsync(1000, blockHash, func(receipts []*ethrpc.TxReceiptJSONRPC, err error) {
		defer close(fetched)
		assert.Regexp(t, "FF23069", err)
		assert.Nil(t, receipts)
	})
	<-fetched
}

func TestTrustedModeSnapshotMonitoredHeadChainReturnsEmpty(t *testing.T) {
	_, bl, _, done := newTestTrustedBlockListener(t)
	defer done()
	assert.Empty(t, bl.SnapshotMonitoredHeadChain())
}
