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
	"strconv"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-evmconnect/mocks/jsonrpcmocks"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func testEventStream(t *testing.T, listeners ...*ffcapi.EventListenerAddRequest) (*eventStream, chan *ffcapi.ListenerEvent, *jsonrpcmocks.Client, func()) {
	ctx, c, mRPC, done := newTestConnector(t)
	mockStreamLoopEmpty(mRPC)
	return testEventStreamExistingConnector(t, ctx, done, c, mRPC, listeners...)
}

func testEventStreamExistingConnector(t *testing.T, ctx context.Context, done func(), c *ethConnector, mRPC *jsonrpcmocks.Client, listeners ...*ffcapi.EventListenerAddRequest) (*eventStream, chan *ffcapi.ListenerEvent, *jsonrpcmocks.Client, func()) {
	events := make(chan *ffcapi.ListenerEvent)
	esID := fftypes.NewUUID()
	_, _, err := c.EventStreamStart(ctx, &ffcapi.EventStreamStartRequest{
		ID:               esID,
		StreamContext:    ctx,
		EventStream:      events,
		BlockListener:    make(chan<- *ffcapi.BlockHashEvent),
		InitialListeners: listeners,
	})
	assert.NoError(t, err)
	es := c.eventStreams[*esID]
	es.c.eventFilterPollingInterval = 1 * time.Millisecond
	es.c.retry.MaximumDelay = 1 * time.Microsecond
	assert.NotNil(t, es)
	return es, events, mRPC, func() {
		done()
		_, _, err := c.EventStreamStopped(ctx, &ffcapi.EventStreamStoppedRequest{
			ID: esID,
		})
		assert.NoError(t, err)
	}
}

func TestAddEventListenerMissingFilters(t *testing.T) {

	es, _, _, done := testEventStream(t)
	defer done()

	_, err := es.addEventListener(es.ctx, &ffcapi.EventListenerAddRequest{
		StreamID:             es.id,
		ListenerID:           fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{},
	})
	assert.Regexp(t, "FF23035", err)

}

func TestAddEventListenerMissingFilterEvent(t *testing.T) {

	es, _, _, done := testEventStream(t)
	defer done()

	_, err := es.addEventListener(es.ctx, &ffcapi.EventListenerAddRequest{
		StreamID:   es.id,
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{}`),
			},
		},
	})
	assert.Regexp(t, "FF23035", err)

}

func TestAddEventListenerBadFilterEvent(t *testing.T) {

	es, _, _, done := testEventStream(t)
	defer done()

	_, err := es.addEventListener(es.ctx, &ffcapi.EventListenerAddRequest{
		StreamID:   es.id,
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":{"inputs":[{"type":"wrong"}]}}`),
			},
		},
	})
	assert.Regexp(t, "FF23033", err)

}

func TestAddEventListenerMultipleEvents(t *testing.T) {

	es, _, _, done := testEventStream(t)
	defer done()

	l, err := es.addEventListener(es.ctx, &ffcapi.EventListenerAddRequest{
		StreamID:   es.id,
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"address":"0xe48C2eF8263fE160BF384cf621AAc36B82a49CE0","event":` + abiTransferEvent + `}`),
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options: fftypes.JSONAnyPtr(`{}`),
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "[0xe48c2ef8263fe160bf384cf621aac36b82a49ce0:Transfer(address,address,uint256),*:Transfer(address,address,uint256)]", l.config.signature)

}

func TestAddEventListenerBadOptions(t *testing.T) {

	es, _, _, done := testEventStream(t)
	defer done()

	_, err := es.addEventListener(es.ctx, &ffcapi.EventListenerAddRequest{
		StreamID:   es.id,
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options: fftypes.JSONAnyPtr(`{"bad json!`),
		},
	})
	assert.Regexp(t, "FF23033", err)

}

func TestAddEventListenerBadInitialBlock(t *testing.T) {

	es, _, _, done := testEventStream(t)
	defer done()

	_, err := es.addEventListener(es.ctx, &ffcapi.EventListenerAddRequest{
		StreamID:   es.id,
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: "wrong",
		},
	})
	assert.Regexp(t, "FF23034", err)

}

func TestStartHeadBlockLimitedByChainHead(t *testing.T) {

	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: "50000000", // will limit to chain head
		},
	}

	es, _, _, done := testEventStream(t, l1req)
	defer done()

	assert.Equal(t, int64(testHighBlock), es.headBlock)
}

func TestCatchupThenRejoinLeadGroup(t *testing.T) {

	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: "12001", // this will establish the position of the head group, starting in catchup, then moving to normal
		},
	}

	es, events, mRPC, done := testEventStream(t, l1req)
	defer done()

	l2req := &ffcapi.EventListenerAddRequest{
		StreamID:   es.id,
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: "1000",
		},
	}

	listenerCaughtUp := make(chan struct{})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getLogs", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		ethLogs := make([]*logJSONRPC, 0)
		filter := *args[3].(*logFilterJSONRPC)
		fromBlock := filter.FromBlock.BigInt().Int64()
		switch fromBlock {
		case 1000:
			ethLogs = append(ethLogs, &logJSONRPC{
				BlockNumber:      ethtypes.NewHexInteger64(1024),
				TransactionIndex: ethtypes.NewHexInteger64(64),
				LogIndex:         ethtypes.NewHexInteger64(2),
				BlockHash:        ethtypes.MustNewHexBytes0xPrefix("0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"),
				Topics: []ethtypes.HexBytes0xPrefix{
					ethtypes.MustNewHexBytes0xPrefix("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
					ethtypes.MustNewHexBytes0xPrefix("0x0000000000000000000000003968ef051b422d3d1cdc182a88bba8dd922e6fa4"),
					ethtypes.MustNewHexBytes0xPrefix("0x000000000000000000000000d0f2f5103fd050739a9fb567251bc460cc24d091"),
				},
				Data: ethtypes.MustNewHexBytes0xPrefix("0x00000000000000000000000000000000000000000000000000000000000003e8"),
			})
		case 6000:
			close(listenerCaughtUp)
		default:
			<-listenerCaughtUp // hold the main group back until we've done the listener catchup
		}
		*args[1].(*[]*logJSONRPC) = ethLogs
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c", false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1024),
			Hash:   ethtypes.MustNewHexBytes0xPrefix("0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"),
		}
	})

	_, _, err := es.c.EventListenerAdd(es.ctx, l2req)
	assert.NoError(t, err)
	l := es.listeners[*l2req.ListenerID]
	assert.True(t, l.catchup)

	e := <-events
	assert.Equal(t, uint64(1024), e.Event.ID.BlockNumber)
	assert.Equal(t, uint64(64), e.Event.ID.TransactionIndex)
	assert.Equal(t, uint64(2), e.Event.ID.LogIndex)
	assert.Equal(t, int64(1024), e.Checkpoint.(*listenerCheckpoint).Block)
	assert.Equal(t, int64(64), e.Checkpoint.(*listenerCheckpoint).TransactionIndex)
	assert.Equal(t, int64(2), e.Checkpoint.(*listenerCheckpoint).LogIndex)
	assert.NotNil(t, e.Event)
	assert.Equal(t, "0x3968ef051b422d3d1cdc182a88bba8dd922e6fa4", e.Event.Data.JSONObject().GetString("from"))
	assert.Equal(t, "0xd0f2f5103fd050739a9fb567251bc460cc24d091", e.Event.Data.JSONObject().GetString("to"))
	assert.Equal(t, "1000", e.Event.Data.JSONObject().GetString("value"))

	<-listenerCaughtUp

	// Confirm the listener joins the group
	started := time.Now()
	for {
		assert.True(t, time.Since(started) < 5*time.Second)
		if l.catchup {
			time.Sleep(1 * time.Microsecond)
			continue
		}
		if es.headBlock != testHighBlock-es.c.checkpointBlockGap {
			time.Sleep(1 * time.Microsecond)
			continue
		}
		break
	}
}

func TestLeadGroupDeliverEvents(t *testing.T) {

	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"address":"0xc89E46EEED41b777ca6625d37E1Cc87C5c037828","event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: strconv.Itoa(testHighBlock),
		},
	}

	ctx, c, mRPC, done := newTestConnector(t)

	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*ethtypes.HexInteger) = *ethtypes.NewHexInteger64(testHighBlock)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newFilter", mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			*args[1].(*string) = "filter_id1"
		}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterLogs", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = make([]*logJSONRPC, 0)
	}).Maybe()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = []*logJSONRPC{
			{
				BlockNumber:      ethtypes.NewHexInteger64(1024),
				TransactionIndex: ethtypes.NewHexInteger64(64),
				LogIndex:         ethtypes.NewHexInteger64(2),
				BlockHash:        ethtypes.MustNewHexBytes0xPrefix("0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"),
				Address:          ethtypes.MustNewAddress("0xc89E46EEED41b777ca6625d37E1Cc87C5c037828"),
				Topics: []ethtypes.HexBytes0xPrefix{
					ethtypes.MustNewHexBytes0xPrefix("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
					ethtypes.MustNewHexBytes0xPrefix("0x0000000000000000000000003968ef051b422d3d1cdc182a88bba8dd922e6fa4"),
					ethtypes.MustNewHexBytes0xPrefix("0x000000000000000000000000d0f2f5103fd050739a9fb567251bc460cc24d091"),
				},
				Data: ethtypes.MustNewHexBytes0xPrefix("0x00000000000000000000000000000000000000000000000000000000000003e8"),
			},
		}
	}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getBlockByHash", "0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c", false).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(**blockInfoJSONRPC) = &blockInfoJSONRPC{
			Number: ethtypes.NewHexInteger64(1024),
			Hash:   ethtypes.MustNewHexBytes0xPrefix("0x6b012339fbb85b70c58ecfd97b31950c4a28bcef5226e12dbe551cb1abaf3b4c"),
		}
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = []*logJSONRPC{}
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_uninstallFilter", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*bool) = true
	}).Maybe()

	_, events, _, done := testEventStreamExistingConnector(t, ctx, done, c, mRPC, l1req)
	defer done()

	e := <-events
	assert.Equal(t, uint64(1024), e.Event.ID.BlockNumber)
	assert.Equal(t, uint64(64), e.Event.ID.TransactionIndex)
	assert.Equal(t, uint64(2), e.Event.ID.LogIndex)
	assert.Equal(t, int64(1024), e.Checkpoint.(*listenerCheckpoint).Block)
	assert.Equal(t, int64(64), e.Checkpoint.(*listenerCheckpoint).TransactionIndex)
	assert.Equal(t, int64(2), e.Checkpoint.(*listenerCheckpoint).LogIndex)
	assert.NotNil(t, e.Event)
	assert.Equal(t, "0x3968ef051b422d3d1cdc182a88bba8dd922e6fa4", e.Event.Data.JSONObject().GetString("from"))
	assert.Equal(t, "0xd0f2f5103fd050739a9fb567251bc460cc24d091", e.Event.Data.JSONObject().GetString("to"))
	assert.Equal(t, "1000", e.Event.Data.JSONObject().GetString("value"))
}

func TestLeadGroupCatchupRetry(t *testing.T) {

	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: "0",
		},
	}
	ctx, c, mRPC, done := newTestConnector(t)

	retried := make(chan struct{})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(testHighBlock)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getLogs", mock.Anything).Return(fmt.Errorf("pop")).
		Run(func(args mock.Arguments) {
			close(retried)
		}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getLogs", mock.Anything).Return(fmt.Errorf("pop"))

	_, _, mRPC, done = testEventStreamExistingConnector(t, ctx, done, c, mRPC, l1req)
	defer done()

	<-retried

}

func TestStreamLoopNewFilterFail(t *testing.T) {

	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: strconv.Itoa(testHighBlock),
		},
	}
	ctx, c, mRPC, done := newTestConnector(t)

	retried := make(chan struct{})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(testHighBlock)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newFilter", mock.Anything).Return(fmt.Errorf("pop")).
		Run(func(args mock.Arguments) {
			close(retried)
		}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newFilter", mock.Anything).Return(fmt.Errorf("pop")).Maybe()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_uninstallFilter", mock.Anything).Return(fmt.Errorf("pop")).Maybe()

	_, _, mRPC, done = testEventStreamExistingConnector(t, ctx, done, c, mRPC, l1req)
	defer done()

	<-retried

}

func TestStreamLoopChangeFilter(t *testing.T) {

	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"address":"0x171AE0BDd882F7b4C84D5b7FBFA994E39C5a3129","event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: strconv.Itoa(testHighBlock),
		},
	}
	l2req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"address":"0xc1552c7E527f8cb51bbca69c6849a192598FAFe6","event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: strconv.Itoa(testHighBlock),
		},
	}
	ctx, c, mRPC, done := newTestConnector(t)

	var es *eventStream
	reestablishedFilter := make(chan struct{})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(testHighBlock)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newFilter", mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			l2req.StreamID = es.id
			_, _, err := c.EventListenerAdd(ctx, l2req)
			assert.NoError(t, err)
			*args[1].(*string) = "filter_id1"
		}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newFilter", mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			*args[1].(*string) = "filter_id2"
			close(reestablishedFilter)
		})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterLogs", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = make([]*logJSONRPC, 0)
	}).Maybe()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = make([]*logJSONRPC, 0)
	}).Maybe()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_uninstallFilter", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*bool) = true
	}).Maybe()

	es, _, mRPC, done = testEventStreamExistingConnector(t, ctx, done, c, mRPC, l1req)
	defer done()

	<-reestablishedFilter

}

func TestStreamLoopFilterReset(t *testing.T) {

	l1req := &ffcapi.EventListenerAddRequest{
		ListenerID: fftypes.NewUUID(),
		EventListenerOptions: ffcapi.EventListenerOptions{
			Filters: []fftypes.JSONAny{
				*fftypes.JSONAnyPtr(`{"address":"0x171AE0BDd882F7b4C84D5b7FBFA994E39C5a3129","event":` + abiTransferEvent + `}`),
			},
			Options:   fftypes.JSONAnyPtr(`{}`),
			FromBlock: strconv.Itoa(testHighBlock),
		},
	}
	ctx, c, mRPC, done := newTestConnector(t)

	reestablishedFilter := make(chan struct{})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_blockNumber").Return(nil).Run(func(args mock.Arguments) {
		hbh := args[1].(*ethtypes.HexInteger)
		*hbh = *ethtypes.NewHexInteger64(testHighBlock)
	})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newFilter", mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			*args[1].(*string) = "filter_id1"
		}).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_newFilter", mock.Anything).Return(nil).
		Run(func(args mock.Arguments) {
			*args[1].(*string) = "filter_id2"
			close(reestablishedFilter)
		})
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterLogs", mock.Anything).Return(fmt.Errorf("filter not found")).Once()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterLogs", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = make([]*logJSONRPC, 0)
	}).Maybe()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_getFilterChanges", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*[]*logJSONRPC) = make([]*logJSONRPC, 0)
	}).Maybe()
	mRPC.On("Invoke", mock.Anything, mock.Anything, "eth_uninstallFilter", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		*args[1].(*bool) = true
	}).Maybe()

	_, _, mRPC, done = testEventStreamExistingConnector(t, ctx, done, c, mRPC, l1req)
	defer done()

	<-reestablishedFilter

}

func TestDispatchListenerDone(t *testing.T) {

	doneCtx, cancel := context.WithCancel(context.Background())
	cancel()
	es := &eventStream{
		ctx:    doneCtx,
		events: make(chan<- *ffcapi.ListenerEvent),
	}
	exiting := es.dispatchSetHWMCheckExit(&aggregatedListener{}, ffcapi.ListenerEvents{
		{},
	}, -1)
	assert.True(t, exiting)

}

func TestGetListenerHWMNotFound(t *testing.T) {

	es := &eventStream{
		ctx:       context.Background(),
		events:    make(chan<- *ffcapi.ListenerEvent),
		listeners: make(map[fftypes.UUID]*listener),
	}
	_, rc, err := es.getListenerHWM(context.Background(), fftypes.NewUUID())
	assert.Regexp(t, "FF23043", err)
	assert.Equal(t, ffcapi.ErrorReasonNotFound, rc)

}
