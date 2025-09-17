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
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const testBlockFilterID1 = "block_filter_1"
const testBlockFilterID2 = "block_filter_2"
const testLogsFilterID1 = "log_filter_1"
const testLogsFilterID2 = "log_filter_2"

func TestBlockListenerStartGettingHighestBlockRetry(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").
		Return(&rpcbackend.RPCError{Message: "pop"}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(12345)
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Maybe()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Maybe()

	h, ok := bl.getHighestBlock(bl.ctx)
	assert.Equal(t, uint64(12345), h)
	assert.True(t, ok)
	done() // Stop immediately in this case, while we're in the polling interval

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerStartGettingHighestBlockFailBeforeStop(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		filterID := args[1].(*string)
		*filterID = testBlockFilterID1
	}).Maybe()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Maybe()
	done() // Stop before we start
	bl := c.blockListener

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").
		Return(&rpcbackend.RPCError{Message: "pop"}).Once()

	h, ok := bl.getHighestBlock(bl.ctx)
	assert.False(t, ok)
	assert.Equal(t, uint64(0), h)

	<-bl.listenLoopDone

	mRPC.AssertExpectations(t)

}

func TestBlockListenerOKSequential(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond
	bl.unstableHeadLength = 2 // check wrapping

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
				block1002Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1003Hash,
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002Hash,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003Hash,
			ParentHash: block1002Hash,
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001Hash.String(),
		block1002Hash.String(),
	}, bu.BlockHashes)
	bu = <-updates
	assert.Equal(t, []string{
		block1003Hash.String(),
	}, bu.BlockHashes)
	assert.False(t, bu.GapPotential)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)

	assert.Equal(t, bl.unstableHeadLength, bl.canonicalChain.Len())

}

func TestBlockListenerWSShoulderTap(t *testing.T) {

	failedConnectOnce := false
	failedSubOnce := false
	toServer, fromServer, url, wsDone := wsclient.NewTestWSServer(func(req *http.Request) {
		if !failedConnectOnce {
			failedConnectOnce = true
			panic("fail once here")
		}
	})

	ctx, c, _, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t, func(conf config.Section) {
		conf.Set(wsclient.WSConfigURL, url)
		conf.Set(wsclient.WSConfigKeyInitialConnectAttempts, 0)
		conf.Set(WebSocketsEnabled, true)
		conf.Set(BlockPollingInterval, "100s") // so the test would just hang if no WS notifications
	})
	svrDone := make(chan struct{})
	bl := c.blockListener

	pingerDone := make(chan struct{})
	complete := false
	go func() {
		defer close(svrDone)
		for {
			select {
			case rpcStr := <-toServer:
				var rpcReq rpcbackend.RPCRequest
				err := json.Unmarshal([]byte(rpcStr), &rpcReq)
				assert.NoError(t, err)
				rpcRes := &rpcbackend.RPCResponse{
					JSONRpc: rpcReq.JSONRpc,
					ID:      rpcReq.ID,
				}
				switch rpcReq.Method {
				case "eth_blockNumber":
					rpcRes.Result = fftypes.JSONAnyPtr(`"0x12345"`)
				case "eth_subscribe":
					assert.Equal(t, "newHeads", rpcReq.Params[0].AsString())
					if !failedSubOnce {
						failedSubOnce = true
						rpcRes.Error = &rpcbackend.RPCError{
							Code:    int64(rpcbackend.RPCCodeInternalError),
							Message: "pop",
						}
					} else {
						rpcRes.Result = fftypes.JSONAnyPtr(fmt.Sprintf(`"%s"`, fftypes.NewUUID()))
						// Spam with notifications
						go func() {
							defer close(pingerDone)
							for !complete {
								time.Sleep(100 * time.Microsecond)
								if bl.newHeadsSub != nil {
									bl.newHeadsSub.Notifications() <- &rpcbackend.RPCSubscriptionNotification{
										CurrentSubID: bl.newHeadsSub.LocalID().String(),
										Result:       fftypes.JSONAnyPtr(`"anything"`),
									}
								}
							}
						}()
					}
				case "eth_newBlockFilter":
					rpcRes.Result = fftypes.JSONAnyPtr(fmt.Sprintf(`"%s"`, fftypes.NewUUID()))
				case "eth_getFilterChanges":
					// ok we can close - the shoulder tap worked
					complete = true
					<-pingerDone
					go done()
				default:
					assert.Fail(t, "unexpected RPC call: %+v", rpcReq)
				}
				b, err := json.Marshal(rpcRes)
				assert.NoError(t, err)
				fromServer <- string(b)
			case <-ctx.Done():
				return
			}
		}
	}()

	bl.checkAndStartListenerLoop()

	// Wait until we close because it worked
	<-bl.listenLoopDone
	assert.True(t, failedConnectOnce)
	assert.True(t, failedSubOnce)

	wsDone()
	<-svrDone
}

func TestBlockListenerOKDuplicates(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	// wait for consumer to be added before returning get filter changes
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
				block1002Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		if len(bl.consumers) > 0 {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
				block1002Hash,
			}
		} else {
			mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
				hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
				*hbh = []ethtypes.HexBytes0xPrefix{
					block1001Hash,
					block1002Hash,
				}
			}).Once()
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1003Hash,
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1002Hash,
			block1003Hash,
		}
		go done() // once we've detected these duplicates, we can close
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002Hash,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003Hash,
			ParentHash: block1002Hash,
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001Hash.String(),
		block1002Hash.String(),
	}, bu.BlockHashes)
	bu = <-updates
	assert.Equal(t, []string{
		block1003Hash.String(),
	}, bu.BlockHashes)
	assert.False(t, bu.GapPotential)

	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)

}

func TestBlockListenerReorgKeepLatestHeadInSameBatch(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String()) // parent
	block1001HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1001HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001HashA,
				block1001HashB,
				block1002Hash,
				block1003Hash,
			}
		})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001HashA,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001HashB.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001HashB,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002Hash,
			ParentHash: block1001HashB,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003Hash,
			ParentHash: block1002Hash,
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001HashB.String(),
		block1002Hash.String(),
		block1003Hash.String(),
	}, bu.BlockHashes)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)
}

func TestBlockListenerReorgKeepLatestHeadInSameBatchValidHashFirst(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String()) // parent
	block1001HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1001HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001HashB, // valid hash is in the front of the array, so will need to re-build the chain
				block1001HashA,
				block1002Hash,
				block1003Hash,
			}
		})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1001
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001HashB,
			ParentHash: block1000Hash,
		}
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1002
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002Hash,
			ParentHash: block1001HashB,
		}
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1003
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003Hash,
			ParentHash: block1002Hash,
		}
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1004 // not found
	}), false).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001HashA,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001HashB.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001HashB,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002Hash,
			ParentHash: block1001HashB,
		}
	})
	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001HashB.String(),
		block1002Hash.String(),
		block1003Hash.String(),
	}, bu.BlockHashes)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)
}

func TestBlockListenerReorgKeepLatestMiddleInSameBatch(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String()) // parent
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
				block1002HashA,
				block1002HashB,
				block1003Hash,
			}
		})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002HashA,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002HashB.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002HashB,
			ParentHash: block1001Hash,
		}
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003Hash,
			ParentHash: block1002HashB,
		}
	})
	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001Hash.String(),
		block1002HashB.String(),
		block1003Hash.String(),
	}, bu.BlockHashes)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)
}

func TestBlockListenerReorgKeepLatestTailInSameBatch(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String()) // parent
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
				block1002Hash,
				block1003HashA,
				block1003HashB,
			}
		})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002Hash,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashA,
			ParentHash: block1002Hash,
		}
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003HashB.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashB,
			ParentHash: block1002Hash,
		}
	})
	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001Hash.String(),
		block1002Hash.String(),
		block1003HashB.String(),
	}, bu.BlockHashes)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)
}

func TestBlockListenerReorgReplaceTail(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
				block1002Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1003HashA,
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1003HashB,
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002Hash,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashA,
			ParentHash: block1002Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003HashB.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashB,
			ParentHash: block1002Hash,
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001Hash.String(),
		block1002Hash.String(),
	}, bu.BlockHashes)
	bu = <-updates
	assert.Equal(t, []string{
		block1003HashA.String(),
	}, bu.BlockHashes)
	assert.False(t, bu.GapPotential)
	bu = <-updates
	assert.Equal(t, []string{
		block1003HashB.String(),
	}, bu.BlockHashes)
	assert.False(t, bu.GapPotential)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)

}

func TestBlockListenerGap(t *testing.T) {

	// See issue https://github.com/hyperledger/firefly-evmconnect/issues/10
	// We have seen that certain JSON/RPC endpoints might miss blocks during re-orgs, and our listener
	// needs to cope with this. This means winding back when we find a gap and re-building our canonical
	// view of the chain.

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1004Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1005Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
				block1002HashA,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1004Hash,
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002HashA,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1004Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1004),
			Hash:       block1004Hash,
			ParentHash: block1003Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1001
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1002
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002HashB,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1003
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003Hash,
			ParentHash: block1002HashB,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1004
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1004),
			Hash:       block1004Hash,
			ParentHash: block1003Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1005
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1005), // this one pops in while we're rebuilding
			Hash:       block1005Hash,
			ParentHash: block1004Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1006 // not found
	}), false).Return(nil)

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001Hash.String(),
		block1002HashA.String(),
	}, bu.BlockHashes)
	bu = <-updates
	assert.Equal(t, []string{
		block1002HashB.String(),
		block1003Hash.String(), // The gap we filled in
		block1004Hash.String(),
		block1005Hash.String(), // Appeared while we were rebuilding our chain
	}, bu.BlockHashes)
	assert.False(t, bu.GapPotential)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1005), bl.highestBlock)

	mRPC.AssertExpectations(t)

}

func TestBlockListenerReorgWhileRebuilding(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1000Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1001Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1003HashA,
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1001Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashA,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1001
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1001),
			Hash:       block1001Hash,
			ParentHash: block1000Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1002
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002HashA,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1003
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashB, // this is a re-org'd block, so we stop here as if we've found the end of the chain
			ParentHash: block1002HashB,
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1001Hash.String(),
	}, bu.BlockHashes)
	bu = <-updates
	assert.Equal(t, []string{
		block1002HashA.String(),
	}, bu.BlockHashes)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)

}

func TestBlockListenerReorgReplaceWholeCanonicalChain(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	block1001Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashA := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1002HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003HashB := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1002HashA,
				block1003HashA,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
		*hbh = []ethtypes.HexBytes0xPrefix{
			block1003HashB,
		}
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1002HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002HashA,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003HashA.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashA,
			ParentHash: block1002HashA,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003HashB.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashB,
			ParentHash: block1002HashB,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1002
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1002),
			Hash:       block1002HashB,
			ParentHash: block1001Hash,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1003
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003HashB,
			ParentHash: block1002HashB,
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.MatchedBy(func(bn *ethtypes.HexInteger) bool {
		return bn.BigInt().Int64() == 1004 // not found
	}), false).Return(nil)

	updates := make(chan *ffcapi.BlockHashEvent)
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     context.Background(),
		updates: updates,
	})

	bu := <-updates
	assert.Equal(t, []string{
		block1002HashA.String(),
		block1003HashA.String(),
	}, bu.BlockHashes)
	bu = <-updates
	assert.Equal(t, []string{
		block1002HashB.String(),
		block1003HashB.String(),
	}, bu.BlockHashes)
	assert.False(t, bu.GapPotential)

	done()
	<-bl.listenLoopDone

	assert.Equal(t, uint64(1003), bl.highestBlock)

	mRPC.AssertExpectations(t)

}

func TestBlockListenerClosed(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond
	block1002Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1003Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		if len(bl.consumers) == 0 {
			go done() // Close after we've processed the log
		}
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003Hash.String()
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number:     ethtypes.NewHexInteger64(1003),
			Hash:       block1003Hash,
			ParentHash: block1002Hash,
		}
	})

	updates := make(chan *ffcapi.BlockHashEvent)
	cancelledCtx, cCancel := context.WithCancel(context.Background())
	cCancel()
	bl.addConsumer(context.Background(), &blockUpdateConsumer{
		id:      fftypes.NewUUID(),
		ctx:     cancelledCtx,
		updates: updates,
	})

	c.WaitClosed()
	mRPC.AssertExpectations(t)

}

func TestBlockListenerBlockNotFound(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1003Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		go done() // Close after we've processed the log
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003Hash.String()
	}), false).Return(nil)

	bl.checkAndStartListenerLoop()

	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerBlockHashFailed(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond
	block1003Hash := ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String())

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1003Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		go done() // Close after we've processed the log
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == block1003Hash.String()
	}), false).Return(&rpcbackend.RPCError{Message: "pop"})

	bl.checkAndStartListenerLoop()

	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerProcessNonStandardHashRejectedWhenNotInHederaCompatibilityMode(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond
	bl.hederaCompatibilityMode = false

	block1003Hash := ethtypes.MustNewHexBytes0xPrefix("0xef177df3b87beed681b1557e8ba7c3ecbd7e4db83d87b66c1e86aa484937ab93f1fae0eb6d4b24ca30aee13f29c83cc9")

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1003Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		go done() // Close after we've processed the log
	})

	bl.checkAndStartListenerLoop()

	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerProcessNonStandardHashRejectedWhenWrongSizeForHedera(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond
	bl.hederaCompatibilityMode = true

	block1003Hash := ethtypes.MustNewHexBytes0xPrefix("0xef")

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1003Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		go done() // Close after we've processed the log
	})

	bl.checkAndStartListenerLoop()

	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerProcessNonStandardHashAcceptedWhenInHederaCompatbilityMode(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond
	bl.hederaCompatibilityMode = true

	block1003Hash := ethtypes.MustNewHexBytes0xPrefix("0xef177df3b87beed681b1557e8ba7c3ecbd7e4db83d87b66c1e86aa484937ab93f1fae0eb6d4b24ca30aee13f29c83cc9")
	truncatedBlock1003Hash := ethtypes.MustNewHexBytes0xPrefix("0xef177df3b87beed681b1557e8ba7c3ecbd7e4db83d87b66c1e86aa484937ab93")

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	conditionalMockOnce(
		mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(nil),
		func() bool { return len(bl.consumers) > 0 },
		func(args mock.Arguments) {
			hbh := args[1].(*[]ethtypes.HexBytes0xPrefix)
			*hbh = []ethtypes.HexBytes0xPrefix{
				block1003Hash,
			}
		})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		go done() // Close after we've processed the log
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == truncatedBlock1003Hash.String()
	}), false).Return(&rpcbackend.RPCError{Message: "pop"})

	bl.checkAndStartListenerLoop()

	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerReestablishBlockFilter(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID2
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", testBlockFilterID1).Return(&rpcbackend.RPCError{Message: "filter not found"}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		go done() // Close after we've processed the log
	})

	bl.checkAndStartListenerLoop()

	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerReestablishBlockFilterFail(t *testing.T) {
	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(&rpcbackend.RPCError{Message: "pop"}).Run(func(args mock.Arguments) {
		go done()
	})

	bl.checkAndStartListenerLoop()

	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerWillNotCloseBlockFilterSignalChannelMoreThanOnce(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		go done()
	})

	loopCount := 100
	loopDone := make(chan struct{}, loopCount)
	for i := 0; i < loopCount; i++ {
		go func() {
			bl.checkAndStartListenerLoop() // start block listener loop
			loopDone <- struct{}{}
		}()
	}

	resultCount := 0
	for {
		select {
		case <-loopDone:
			resultCount++
		}
		if resultCount == loopCount {
			break
		}
	}

	bl.waitUntilStarted(context.Background())
	c.WaitClosed()

	mRPC.AssertExpectations(t)

}

func TestBlockListenerWaitUntilStartedOnlyReturnsAfterEstablishingBlockFilter(t *testing.T) {
	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.blockPollingInterval = 1 * time.Microsecond

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(1000)
	}).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_newBlockFilter").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*string)
		*hbh = testBlockFilterID1
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil)

	assert.False(t, bl.isStarted)
	bl.checkAndStartListenerLoop()
	bl.waitUntilStarted(context.Background())
	assert.True(t, bl.isStarted)
	_, ok := <-bl.startDone
	if ok {
		t.Errorf("Expected new block filter established signal channel to be closed")
	}

	done()
	c.WaitClosed()

	mRPC.AssertExpectations(t)
}

func TestBlockListenerDispatchStopped(t *testing.T) {
	_, c, _, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	done()

	c.blockListener.dispatchToConsumers([]*blockUpdateConsumer{
		{id: fftypes.NewUUID(), ctx: context.Background(), updates: make(chan<- *ffcapi.BlockHashEvent)},
	}, &ffcapi.BlockHashEvent{
		BlockHashes: []string{},
	})
}

func TestBlockListenerRebuildCanonicalChainEmpty(t *testing.T) {

	_, c, _, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	defer done()
	bl := c.blockListener

	res := bl.rebuildCanonicalChain()
	assert.Nil(t, res)

}

func TestBlockListenerRebuildCanonicalFailTerminate(t *testing.T) {

	_, c, mRPC, done := newTestConnectorWithNoBlockerFilterDefaultMocks(t)
	bl := c.blockListener
	bl.canonicalChain.PushBack(&ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(1000),
		BlockHash:   ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String()).String(),
		ParentHash:  ethtypes.MustNewHexBytes0xPrefix(fftypes.NewRandB32().String()).String(),
	})

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByNumber", mock.Anything, false).
		Return(&rpcbackend.RPCError{Message: "pop"}).
		Run(func(args mock.Arguments) {
			done()
		})

	res := bl.rebuildCanonicalChain()
	assert.Nil(t, res)

	mRPC.AssertExpectations(t)
}
