// Copyright © 2022 Kaleido, Inc.
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
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestBlockListenerStartGettingHighestBlockRetry(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	bl := c.blockListener

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").
		Return(fmt.Errorf("pop")).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(12345)
	})

	assert.Equal(t, int64(12345), bl.getHighestBlock(bl.ctx))
	done() // Stop immediately in this case, while we're in the polling interval

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerStartGettingHighestBlockFailBeforeStop(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	done() // Stop before we start
	bl := c.blockListener

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").
		Return(fmt.Errorf("pop")).Maybe()

	assert.Equal(t, int64(-1), bl.getHighestBlock(bl.ctx))

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerOK(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(**ethtypes.HexInteger)
		*hbh = ethtypes.NewHexInteger64(101010)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.MatchedBy(func(filter *ethtypes.HexInteger) bool {
		return filter.BigInt().Int64() == 101010
	})).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			ethtypes.MustNewHexBytes0xPrefix("0x936feb38eae37a1083a995a33795d952ae502017bb749d2566ed5ad0cb3b49e1"),
			ethtypes.MustNewHexBytes0xPrefix("0x67e48f436893ff6b1bd5303a14dad1f4981441b2990e72d31dc2678faa55f38c"),
		}
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.MatchedBy(func(filter *ethtypes.HexInteger) bool {
		return filter.BigInt().Int64() == 101010
	})).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			ethtypes.MustNewHexBytes0xPrefix("0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"),
		}
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x936feb38eae37a1083a995a33795d952ae502017bb749d2566ed5ad0cb3b49e1"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1001),
		}
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x67e48f436893ff6b1bd5303a14dad1f4981441b2990e72d31dc2678faa55f38c"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1002),
		}
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1003),
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(&blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		"0x936feb38eae37a1083a995a33795d952ae502017bb749d2566ed5ad0cb3b49e1",
		"0x67e48f436893ff6b1bd5303a14dad1f4981441b2990e72d31dc2678faa55f38c",
	}, bu.BlockHashes)
	bu = <-updates
	assert.Equal(t, []string{
		"0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42",
	}, bu.BlockHashes)
	assert.False(t, bu.GapPotential)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, int64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)

}

func TestBlockListenerClosed(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(**ethtypes.HexInteger)
		*hbh = ethtypes.NewHexInteger64(101010)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.MatchedBy(func(filter *ethtypes.HexInteger) bool {
		return filter.BigInt().Int64() == 101010
	})).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			ethtypes.MustNewHexBytes0xPrefix("0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"),
		}
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		done() // Close after we've processed the log
	})

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1003),
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	cancelledCtx, cCancel := context.WithCancel(context.Background())
	cCancel()
	bl.addConsumer(&blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     cancelledCtx,
		updates: updates,
	})

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerBlockNotFound(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(**ethtypes.HexInteger)
		*hbh = ethtypes.NewHexInteger64(101010)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.MatchedBy(func(filter *ethtypes.HexInteger) bool {
		return filter.BigInt().Int64() == 101010
	})).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			ethtypes.MustNewHexBytes0xPrefix("0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"),
		}
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		done() // Close after we've processed the log
	})

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"
	}), false).Return(nil)

	bl.checkStartedLocked()

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerBlockHashFailed(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(**ethtypes.HexInteger)
		*hbh = ethtypes.NewHexInteger64(101010)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.MatchedBy(func(filter *ethtypes.HexInteger) bool {
		return filter.BigInt().Int64() == 101010
	})).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			ethtypes.MustNewHexBytes0xPrefix("0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"),
		}
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		done() // Close after we've processed the log
	})

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0xe74ebee74141ef8932666923fae9b8d6cf04ba67989e7908fcddb66565d41e42"
	}), false).Return(fmt.Errorf("pop"))

	bl.checkStartedLocked()

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerReestablishBlockFilter(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(**ethtypes.HexInteger)
		*hbh = ethtypes.NewHexInteger64(101010)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(**ethtypes.HexInteger)
		*hbh = ethtypes.NewHexInteger64(202020)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.MatchedBy(func(filter *ethtypes.HexInteger) bool {
		return filter.BigInt().Int64() == 101010
	})).Return(fmt.Errorf("filter not found")).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		done() // Close after we've processed the log
	})

	bl.checkStartedLocked()

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerReestablishBlockFilterFail(t *testing.T) {

	_, c, mRPC, done := newTestConnector(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(fmt.Errorf("pop")).Run(func(args mock.Arguments) {
		done()
	})

	bl.checkStartedLocked()

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}
