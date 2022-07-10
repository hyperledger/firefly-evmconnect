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
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"sync"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// listenerCheckpoint is our Ethereum specific custom options that can be specified when creating a listener
type listenerOptions struct {
	Methods []*abi.Entry `json:"methods,omitempty"` // An optional array of ABI methods. If specified and the input data for a transaction matches, the decoded inputs will be included in the event
}

// listenerCheckpoint is our Ethereum specific checkpoint structure
type listenerCheckpoint struct {
	Block            int64 `json:"block"`
	TransactionIndex int64 `json:"transactionIndex"`
	LogIndex         int64 `json:"logIndex"`
}

// listenerConfig is the configuration parsed from generic FFCAPI connector framework JSON, into our Ethereum specific options
type listenerConfig struct {
	name      string
	fromBlock string
	options   *listenerOptions
	filters   []*eventFilter
	signature string
}

// listener is the state we hold in memory for each individual listener that has been added
type listener struct {
	id            *fftypes.UUID
	c             *ethConnector
	eventStream   *eventStream
	checkpointMux sync.Mutex // Protects checkpoint of an individual listener. May hold ES lock when taking this, must NOT attempt to obtain ES lock while holding this
	checkpoint    *listenerCheckpoint
	config        listenerConfig
	catchup       bool
}

type logFilterJSONRPC struct {
	FromBlock *ethtypes.HexInteger          `json:"fromBlock,omitempty"`
	ToBlock   *ethtypes.HexInteger          `json:"toBlock,omitempty"`
	Address   *ethtypes.Address0xHex        `json:"address,omitempty"`
	Topics    [][]ethtypes.HexBytes0xPrefix `json:"topics,omitempty"`
}

type logJSONRPC struct {
	Removed          bool                        `json:"removed"`
	LogIndex         *fftypes.FFBigInt           `json:"logIndex"`
	TransactionIndex *fftypes.FFBigInt           `json:"transactionIndex"`
	BlockNumber      *fftypes.FFBigInt           `json:"blockNumber"`
	TransactionHash  ethtypes.HexBytes0xPrefix   `json:"transactionHash"`
	BlockHash        ethtypes.HexBytes0xPrefix   `json:"blockHash"`
	Address          *ethtypes.Address0xHex      `json:"address"`
	Data             ethtypes.HexBytes0xPrefix   `json:"data"`
	Topics           []ethtypes.HexBytes0xPrefix `json:"topics"`
}

func (l *listener) getInitialBlock(ctx context.Context, fromBlockInstruction string) (int64, error) {
	if fromBlockInstruction == ffcapi.FromBlockLatest || fromBlockInstruction == "" {
		// Get the latest block number to store in the `FromBlock`
		var fromBlock *fftypes.FFBigInt
		err := l.c.backend.Invoke(ctx, &fromBlock, "eth_blockNumber")
		if err != nil {
			return -1, err // retry indefinitely (only exits if context is cancelled)
		}
		return fromBlock.Int64(), nil
	}
	num, ok := new(big.Int).SetString(fromBlockInstruction, 0)
	if !ok {
		return -1, i18n.NewError(ctx, msgs.MsgInvalidFromBlock, fromBlockInstruction)
	}
	return num.Int64(), nil
}

func parseListenerOptions(ctx context.Context, o *fftypes.JSONAny) (*listenerOptions, error) {
	var options listenerOptions
	if o != nil {
		err := json.Unmarshal(o.Bytes(), &options)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgInvalidListenerOptions, err)
		}
	}
	return &options, nil
}

func (l *listener) start(ctx context.Context) {
	// If the block gap at the point of start is
	if l.checkCatchup(ctx) {
		go l.listenerCatchupLoop()
	}
}

func (l *listener) ensureCheckpoint(ctx context.Context) error {
	l.checkpointMux.Lock()
	defer l.checkpointMux.Unlock()
	if l.checkpoint == nil {
		firstBlock, err := l.getInitialBlock(ctx, l.config.fromBlock)
		if err != nil {
			log.L(ctx).Errorf("Failed to initialize listener: %s", err)
			return err
		}
		// Simulate a checkpoint at the configured fromBlock
		l.checkpoint = &listenerCheckpoint{
			Block: firstBlock,
		}
	}
	return nil
}

func (l *listener) checkCatchup(ctx context.Context) bool {
	l.checkpointMux.Lock()
	defer l.checkpointMux.Unlock()
	// We do a dirty read of the head block (unless the caller has locked the eventStream Mutex, which
	// we support in the mutex hierarchy)
	headBlock := l.eventStream.headBlock
	blockGap := headBlock - l.checkpoint.Block
	l.catchup = blockGap > l.c.catchupThreshold
	log.L(ctx).Debugf("Listener %s catchup=%t head=%d gap=%d", l.id, l.catchup, headBlock, blockGap)
	return l.catchup
}

// listenerCatchupLoop reads pages of blocks at a time, until it gets within the configured catchup-threshold
// of the head of the blockchain.
// Then it moves this listener into the head-set of listeners, which share a common filter, listening
// for new events to arrive at the head of the chain.
func (l *listener) listenerCatchupLoop() {

	// Only filtering on a single listener
	ctx := log.WithLogField(l.eventStream.ctx, "listener", l.id.String())
	al := l.eventStream.buildAggregatedListener([]*listener{l})

	retryCount := 0
	for {
		if !l.checkCatchup(ctx) {
			// We're done with catchup for this listener - it can join the main group
			l.eventStream.rejoinLeadGroup(l)
			log.L(ctx).Infof("Listener completed catchup, and rejoined lead group")
			return
		}

		fromBlock := l.checkpoint.Block
		toBlock := l.checkpoint.Block + l.c.catchupPageSize
		events, err := l.eventStream.getBlockRangeEvents(ctx, al, fromBlock, toBlock)
		if err != nil {
			if l.c.doDelay(l.eventStream.ctx, &retryCount, err) {
				log.L(ctx).Infof("Listener catchup loop exiting")
				return
			}
			continue
		}
		for _, event := range events {
			l.eventStream.events <- event
		}
		retryCount = 0 // Reset on success
	}
}

func (l *listener) decodeLogData(ctx context.Context, event *abi.Entry, topics []ethtypes.HexBytes0xPrefix, data ethtypes.HexBytes0xPrefix) *fftypes.JSONAny {
	v, err := event.DecodeEventDataCtx(ctx, topics, data)
	if err != nil {
		log.L(ctx).Errorf("Failed to decode event: %s", err)
		return nil
	}
	b, err := l.c.serializer.SerializeJSONCtx(ctx, v)
	if err != nil {
		log.L(ctx).Errorf("Failed to serialize event: %s", err)
		return nil
	}
	return fftypes.JSONAnyPtrBytes(b)
}

func (l *listener) matchMethod(ctx context.Context, methods []*abi.Entry, txInfo *txInfoJSONRPC, info *eventInfo) {
	if len(txInfo.Input) < 4 {
		log.L(ctx).Debugf("No function selector available for TX '%s'", txInfo.Hash)
		return
	}
	functionID := txInfo.Input[0:4]
	var method *abi.Entry
	for _, m := range methods {
		if bytes.Equal(method.FunctionSelectorBytes(), functionID) {
			method = m
			break
		}
	}
	if method == nil {
		log.L(ctx).Debugf("Function selector '%s' for TX '%s' does not match any of the supplied methods", functionID.String(), txInfo.Hash)
		return
	}
	info.InputMethod = method.String()
	v, err := method.DecodeCallDataCtx(ctx, txInfo.Input)
	if err != nil {
		log.L(ctx).Warnf("Failed to decode input for TX '%s' using '%s'", txInfo.Hash, info.InputMethod)
		return
	}
	b, err := l.c.serializer.SerializeJSONCtx(ctx, v)
	if err != nil {
		log.L(ctx).Errorf("Failed to serialize function input arguments: %s", err)
		return
	}
	info.InputArgs = fftypes.JSONAnyPtrBytes(b)
	return
}

func (l *listener) filterEnrichEthLog(ctx context.Context, f *eventFilter, ethLog *logJSONRPC) (*ffcapi.ListenerEvent, bool) {

	// Apply a post-filter check to the event
	blockNumber := ethLog.BlockNumber.Int64()
	transactionIndex := ethLog.TransactionIndex.Int64()
	logIndex := ethLog.LogIndex.Int64()
	protoID := getEventProtoID(blockNumber, transactionIndex, logIndex)
	topicMatches := len(ethLog.Topics) > 0 && bytes.Equal(ethLog.Topics[0], f.Topic0)
	addrMatches := f.Address == nil || bytes.Equal(ethLog.Address[:], f.Address[:])
	if !topicMatches || !addrMatches {
		log.L(ctx).Debugf("Listener %s skipping event '%s' topicMatches=%t addrMatches=%t", l.id, protoID, topicMatches, addrMatches)
		return nil, false
	}

	// If this event is behind the current checkpoint, then we ignore it (higher code layers ensure we always have a checkpoint here).
	// This is possible because we aggregate together many listeners for JSON/RPC call efficiency, so after restarts or catchup
	// it's possible for us to replay events on listener1, while finding new events on listener2.
	afterCheckpoint := blockNumber > l.checkpoint.Block || transactionIndex > l.checkpoint.TransactionIndex || logIndex > l.checkpoint.LogIndex
	if !afterCheckpoint {
		log.L(ctx).Debugf("Listener %s skipping event '%s' at or before checkpoint (b=%d,i=%d,l=%d)", l.id, protoID, l.checkpoint.Block, l.checkpoint.TransactionIndex, l.checkpoint.LogIndex)
		return nil, false
	}

	log.L(ctx).Infof("Listener %s detected event '%s'", l.id, protoID)
	data := l.decodeLogData(ctx, f.Event, ethLog.Topics, ethLog.Data)

	info := eventInfo{
		logJSONRPC:      *ethLog,
		DeprecatedSubID: l.id,
		ListenerID:      l.id,
		ListenerName:    l.config.name,
	}

	if l.c.eventBlockTimestamps {
		bi, err := l.c.getBlockInfoByHash(ctx, ethLog.BlockHash.String())
		if bi == nil || err != nil {
			log.L(ctx).Errorf("Failed to get block info timestamp for block '%s': %v", ethLog.BlockHash, err)
		} else {
			info.Timestamp = bi.Timestamp.BigInt().Uint64()
		}
	}

	if len(l.config.options.Methods) > 0 {
		txInfo, err := l.c.getTransactionInfo(ctx, ethLog.TransactionHash)
		if txInfo == nil || err != nil {
			log.L(ctx).Errorf("Failed to get transaction info for TX '%s': %v", ethLog.TransactionHash, err)
		} else {
			info.InputSigner = txInfo.From
			l.matchMethod(ctx, l.config.options.Methods, txInfo, &info)
		}
	}

	infoBytes, _ := json.Marshal(&info)
	cp := listenerCheckpoint{
		Block:            blockNumber,
		TransactionIndex: transactionIndex,
		LogIndex:         logIndex,
	}
	cpb, _ := json.Marshal(&cp)
	return &ffcapi.ListenerEvent{
		Checkpoint: fftypes.JSONAnyPtrBytes(cpb),
		Event: &ffcapi.Event{
			EventID: ffcapi.EventID{
				ListenerID:       l.id,
				BlockHash:        ethLog.BlockHash.String(),
				TransactionHash:  ethLog.TransactionHash.String(),
				BlockNumber:      uint64(blockNumber),
				TransactionIndex: uint64(transactionIndex),
				LogIndex:         uint64(logIndex),
			},
			Info: fftypes.JSONAnyPtrBytes(infoBytes),
			Data: data,
		},
	}, true
}
