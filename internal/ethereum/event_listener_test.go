// Copyright © 2022 Kaleido, Inl.c.
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
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-evmconnect/mocks/rpcbackendmocks"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/net/context"
)

func TestListenerCheckpointLessThan(t *testing.T) {

	assert.True(t, (&listenerCheckpoint{
		Block:            1000,
		TransactionIndex: 10,
		LogIndex:         5,
	}).LessThan(&listenerCheckpoint{
		Block:            2000,
		TransactionIndex: 2,
		LogIndex:         1,
	}))

	assert.True(t, (&listenerCheckpoint{
		Block:            1000,
		TransactionIndex: 10,
		LogIndex:         5,
	}).LessThan(&listenerCheckpoint{
		Block:            1000,
		TransactionIndex: 11,
		LogIndex:         1,
	}))

	assert.True(t, (&listenerCheckpoint{
		Block:            1000,
		TransactionIndex: 10,
		LogIndex:         5,
	}).LessThan(&listenerCheckpoint{
		Block:            1000,
		TransactionIndex: 10,
		LogIndex:         6,
	}))

}

func sampleTransferLog() *logJSONRPC {
	return &logJSONRPC{
		Address:          ethtypes.MustNewAddress("0x20355f3E852D4b6a9944AdA8d5399dDD3409A431"),
		BlockNumber:      ethtypes.NewHexInteger64(1024),
		TransactionIndex: ethtypes.NewHexInteger64(64),
		LogIndex:         ethtypes.NewHexInteger64(2),
		BlockHash:        ethtypes.MustNewHexBytes0xPrefix("0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"),
		TransactionHash:  ethtypes.MustNewHexBytes0xPrefix("0x1a1f797ee000c529b6a2dd330cedd0d081417a30d16a4eecb3f863ab4657246f"),
		Topics: []ethtypes.HexBytes0xPrefix{
			ethtypes.MustNewHexBytes0xPrefix("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
			ethtypes.MustNewHexBytes0xPrefix("0x0000000000000000000000003968ef051b422d3d1cdc182a88bba8dd922e6fa4"),
			ethtypes.MustNewHexBytes0xPrefix("0x000000000000000000000000d0f2f5103fd050739a9fb567251bc460cc24d091"),
		},
		Data: ethtypes.MustNewHexBytes0xPrefix("0x00000000000000000000000000000000000000000000000000000000000003e8"),
	}
}

func newTestListener(t *testing.T, withMethods bool) (*listener, *rpcbackendmocks.Backend, func()) {
	lID := fftypes.NewUUID()
	options := ffcapi.EventListenerOptions{
		Filters: []fftypes.JSONAny{
			*fftypes.JSONAnyPtr(`{"address":"0x20355f3E852D4b6a9944AdA8d5399dDD3409A431","event":` + abiTransferEvent + `}`),
		},
		Options:   fftypes.JSONAnyPtr(`{}`),
		FromBlock: strconv.Itoa(testHighBlock),
	}
	if withMethods {
		options.Options = fftypes.JSONAnyPtr(`{"methods":[` + abiTransferFn + `],"signer":true}`)
	}
	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID:           lID,
		EventListenerOptions: options,
	}

	es, _, mRPC, done := testEventStream(t, l1req)

	l := es.listeners[*lID]
	assert.NotNil(t, l)

	done() // stop it so we can safely call the listener directly
	esCtxReplaced, cancelCtx := context.WithCancel(context.Background())
	es.ctx = esCtxReplaced
	l.catchupLoopDone = make(chan struct{})
	l.hwmBlock = 0

	return l, mRPC, cancelCtx
}

func TestGetInitialBlockTimeout(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, c, mRPC, done := newTestConnector(t)
	defer done()
	l := &listener{
		c: c,
	}

	blockRPC := make(chan struct{})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(fmt.Errorf("pop")).Run(func(args mock.Arguments) {
		<-blockRPC // make it timeout
	})

	_, err := l.getInitialBlock(ctx, "latest")
	assert.Regexp(t, "FF23046", err)

	close(blockRPC)

}

func TestGetHWMNotInit(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, c, mRPC, done := newTestConnector(t)
	defer done()
	l := &listener{
		c: c,
	}

	blockRPC := make(chan struct{})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_blockNumber").Return(fmt.Errorf("pop")).Run(func(args mock.Arguments) {
		<-blockRPC // make it timeout
	})

	_, err := l.getInitialBlock(ctx, "latest")
	assert.Regexp(t, "FF23046", err)

	close(blockRPC)

}

func TestListenerCatchupErrorsThenDeliveryExit(t *testing.T) {

	l, mRPC, cancelCtx := newTestListener(t, false)

	l.catchupLoopDone = make(chan struct{})
	l.hwmBlock = 0

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1001),
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getLogs", mock.Anything).Return(fmt.Errorf("pop")).Once()
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getLogs", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = []*logJSONRPC{sampleTransferLog()}
		// Cancel the context here so we exit pushing the event
		cancelCtx()
	})

	l.listenerCatchupLoop()

}

func TestListenerCatchupErrorThenExit(t *testing.T) {

	l, mRPC, cancelCtx := newTestListener(t, false)

	l.catchupLoopDone = make(chan struct{})
	l.hwmBlock = 0

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getLogs", mock.Anything).Return(fmt.Errorf("pop")).Run(func(args mock.Arguments) {
		cancelCtx()
	})

	l.listenerCatchupLoop()

}

func TestListenerCatchupRemoved(t *testing.T) {

	l, _, _ := newTestListener(t, false)

	l.catchupLoopDone = make(chan struct{})
	l.hwmBlock = 0
	l.removed = true

	l.listenerCatchupLoop()

}

func TestDecodeLogDataFail(t *testing.T) {

	l, _, _ := newTestListener(t, false)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	res := l.decodeLogData(l.es.ctx, abiEvent, []ethtypes.HexBytes0xPrefix{}, nil)
	assert.Nil(t, res)

}

func TestSerializeEventDataFail(t *testing.T) {

	l, _, _ := newTestListener(t, false)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	res := l.decodeLogData(l.es.ctx, abiEvent, []ethtypes.HexBytes0xPrefix{}, nil)
	assert.Nil(t, res)

}

func TestFilterEnrichEthLogBlockBelowHWM(t *testing.T) {

	l, _, _ := newTestListener(t, true)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	l.hwmBlock = 2
	_, ok := l.filterEnrichEthLog(context.Background(), l.config.filters[0], &logJSONRPC{
		BlockNumber: ethtypes.NewHexInteger64(1),
	})
	assert.False(t, ok)

}

func TestFilterEnrichEthLogAddressMismatch(t *testing.T) {

	l, _, _ := newTestListener(t, true)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	_, ok := l.filterEnrichEthLog(context.Background(), l.config.filters[0], &logJSONRPC{
		Address: ethtypes.MustNewAddress("0x20355f3e852d4b6a9944ada8d5399ddd3409a431"),
	})
	assert.False(t, ok)

}

func TestFilterEnrichEthLogMethodInputsOk(t *testing.T) {

	l, mRPC, _ := newTestListener(t, true)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1024),
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionByHash", mock.MatchedBy(func(th ethtypes.HexBytes0xPrefix) bool {
		return th.String() == "0x1a1f797ee000c529b6a2dd330cedd0d081417a30d16a4eecb3f863ab4657246f"
	})).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**txInfoJSONRPC) = &txInfoJSONRPC{
			From:  ethtypes.MustNewAddress("0x3968ef051b422d3d1cdc182a88bba8dd922e6fa4"),
			Input: ethtypes.MustNewHexBytes0xPrefix("0xa9059cbb000000000000000000000000d0f2f5103fd050739a9fb567251bc460cc24d09100000000000000000000000000000000000000000000000000000000000003e8"),
		}
	})

	ev, ok := l.filterEnrichEthLog(context.Background(), l.config.filters[0], sampleTransferLog())
	assert.True(t, ok)
	ei := ev.Event.Info.(*eventInfo)
	assert.NotNil(t, ei.InputArgs)
	assert.Equal(t, `{"_to":"0xd0f2f5103fd050739a9fb567251bc460cc24d091","_value":"1000"}`, ei.InputArgs.String())
	assert.Equal(t, `transfer(address,uint256)`, ei.InputMethod)
	assert.Equal(t, `0x3968ef051b422d3d1cdc182a88bba8dd922e6fa4`, ei.InputSigner.String())

}

func TestFilterEnrichEthLogTXInfoFail(t *testing.T) {

	l, mRPC, _ := newTestListener(t, true)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"
	}), false).Return(fmt.Errorf("pop1"))
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionByHash", mock.MatchedBy(func(th ethtypes.HexBytes0xPrefix) bool {
		return th.String() == "0x1a1f797ee000c529b6a2dd330cedd0d081417a30d16a4eecb3f863ab4657246f"
	})).Return(fmt.Errorf("pop2"))

	ev, ok := l.filterEnrichEthLog(context.Background(), l.config.filters[0], sampleTransferLog())
	assert.True(t, ok)
	ei := ev.Event.Info.(*eventInfo)
	assert.Nil(t, ei.InputArgs)

}

func TestFilterEnrichEthLogMethodBadInputTooShort(t *testing.T) {

	l, mRPC, _ := newTestListener(t, true)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1024),
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionByHash", mock.MatchedBy(func(th ethtypes.HexBytes0xPrefix) bool {
		return th.String() == "0x1a1f797ee000c529b6a2dd330cedd0d081417a30d16a4eecb3f863ab4657246f"
	})).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**txInfoJSONRPC) = &txInfoJSONRPC{
			From:  ethtypes.MustNewAddress("0x3968ef051b422d3d1cdc182a88bba8dd922e6fa4"),
			Input: ethtypes.MustNewHexBytes0xPrefix("0x"),
		}
	})

	ev, ok := l.filterEnrichEthLog(context.Background(), l.config.filters[0], sampleTransferLog())
	assert.True(t, ok)
	ei := ev.Event.Info.(*eventInfo)
	assert.Nil(t, ei.InputArgs)

}

func TestFilterEnrichEthLogMethodBadInputTooMismatchFunctionID(t *testing.T) {

	l, mRPC, _ := newTestListener(t, true)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1024),
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionByHash", mock.MatchedBy(func(th ethtypes.HexBytes0xPrefix) bool {
		return th.String() == "0x1a1f797ee000c529b6a2dd330cedd0d081417a30d16a4eecb3f863ab4657246f"
	})).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**txInfoJSONRPC) = &txInfoJSONRPC{
			From:  ethtypes.MustNewAddress("0x3968ef051b422d3d1cdc182a88bba8dd922e6fa4"),
			Input: ethtypes.MustNewHexBytes0xPrefix("0xfeedbeef"),
		}
	})

	ev, ok := l.filterEnrichEthLog(context.Background(), l.config.filters[0], sampleTransferLog())
	assert.True(t, ok)
	ei := ev.Event.Info.(*eventInfo)
	assert.Nil(t, ei.InputArgs)

}

func TestFilterEnrichEthLogMethodBadInputABIData(t *testing.T) {

	l, mRPC, _ := newTestListener(t, true)

	var abiEvent *abi.Entry
	err := json.Unmarshal([]byte(abiTransferEvent), &abiEvent)
	assert.NoError(t, err)

	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getBlockByHash", mock.MatchedBy(func(bh string) bool {
		return bh == "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"
	}), false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1024),
		}
	})
	mRPC.On("CallRPC", mock.Anything, mock.Anything, "eth_getTransactionByHash", mock.MatchedBy(func(th ethtypes.HexBytes0xPrefix) bool {
		return th.String() == "0x1a1f797ee000c529b6a2dd330cedd0d081417a30d16a4eecb3f863ab4657246f"
	})).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**txInfoJSONRPC) = &txInfoJSONRPC{
			From:  ethtypes.MustNewAddress("0x3968ef051b422d3d1cdc182a88bba8dd922e6fa4"),
			Input: ethtypes.MustNewHexBytes0xPrefix("0xa9059cbb0000000000000000"),
		}
	})

	ev, ok := l.filterEnrichEthLog(context.Background(), l.config.filters[0], sampleTransferLog())
	assert.True(t, ok)
	ei := ev.Event.Info.(*eventInfo)
	assert.Nil(t, ei.InputArgs)

}
