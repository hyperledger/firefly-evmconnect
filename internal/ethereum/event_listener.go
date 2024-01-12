// Copyright © 2024 Kaleido, Inl.c.
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
	Signer  bool         `json:"signer,omitempty"`  // An optional boolean for whether to extract the signer of the transaction that emitted the event
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
	id              *fftypes.UUID
	c               *ethConnector
	es              *eventStream
	hwmMux          sync.Mutex // Protects checkpoint of an individual listener. May hold ES lock when taking this, must NOT attempt to obtain ES lock while holding this
	hwmBlock        int64
	config          listenerConfig
	removed         bool
	catchup         bool
	catchupLoopDone chan struct{}
}

type logFilterJSONRPC struct {
	FromBlock *ethtypes.HexInteger          `json:"fromBlock,omitempty"`
	ToBlock   *ethtypes.HexInteger          `json:"toBlock,omitempty"`
	Address   *ethtypes.Address0xHex        `json:"address,omitempty"`
	Topics    [][]ethtypes.HexBytes0xPrefix `json:"topics,omitempty"`
}

type logJSONRPC struct {
	Removed          bool                        `json:"removed"`
	LogIndex         *ethtypes.HexInteger        `json:"logIndex"`
	TransactionIndex *ethtypes.HexInteger        `json:"transactionIndex"`
	BlockNumber      *ethtypes.HexInteger        `json:"blockNumber"`
	TransactionHash  ethtypes.HexBytes0xPrefix   `json:"transactionHash"`
	BlockHash        ethtypes.HexBytes0xPrefix   `json:"blockHash"`
	Address          *ethtypes.Address0xHex      `json:"address"`
	Data             ethtypes.HexBytes0xPrefix   `json:"data"`
	Topics           []ethtypes.HexBytes0xPrefix `json:"topics"`
}

func (cp *listenerCheckpoint) LessThan(b ffcapi.EventListenerCheckpoint) bool {
	bcp := b.(*listenerCheckpoint)
	return cp.Block < bcp.Block ||
		(cp.Block == bcp.Block &&
			(cp.TransactionIndex < bcp.TransactionIndex ||
				(cp.TransactionIndex == bcp.TransactionIndex && (cp.LogIndex < bcp.LogIndex))))
}

func (l *listener) getInitialBlock(ctx context.Context, fromBlockInstruction string) (int64, error) {
	if fromBlockInstruction == ffcapi.FromBlockLatest || fromBlockInstruction == "" {
		// Get the latest block number of the chain
		chainHead, ok := l.c.blockListener.getHighestBlock(ctx)
		if !ok {
			return -1, i18n.NewError(ctx, msgs.MsgTimedOutQueryingChainHead)
		}
		return chainHead, nil
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

func (l *listener) ensureHWM(ctx context.Context) error {
	l.hwmMux.Lock()
	defer l.hwmMux.Unlock()
	if l.hwmBlock < 0 {
		firstBlock, err := l.getInitialBlock(ctx, l.config.fromBlock)
		if err != nil {
			log.L(ctx).Errorf("Failed to initialize listener: %s", err)
			return err
		}
		// HWM is the configured fromBlock
		l.hwmBlock = firstBlock
	}
	return nil
}

func (l *listener) checkReadyForLeadPackOrRemoved(ctx context.Context) (bool, bool) {
	l.hwmMux.Lock()
	defer l.hwmMux.Unlock()
	// We do a dirty read of the head block (unless the caller has locked the eventStream Mutex, which
	// we support in the mutex hierarchy)
	headBlock := l.es.headBlock
	blockGap := headBlock - l.hwmBlock
	readyForLead := blockGap < l.c.catchupThreshold
	log.L(ctx).Debugf("Listener %s head=%d hwm=%d (gap=%d) readyForLead=%t", l.id, headBlock, l.hwmBlock, blockGap, readyForLead)
	return readyForLead, l.removed
}

// getHWMCheckpoint gets the point the event polling is up to for this listener.
// Note this intentionally does not account for dispatched events, as the parent framework ensures that
// this checkpoint is only persisted when there are no events in-flight pending dispatch for this listener,
// and the checkpoint for this listener is stale.
func (l *listener) getHWMCheckpoint() *listenerCheckpoint {
	l.hwmMux.Lock()
	defer l.hwmMux.Unlock()
	// Generate a checkpoint before the first transaction, in the high watermark block
	log.L(l.es.ctx).Debugf("HWM checkpoint block for '%s': %d", l.id, l.hwmBlock)
	return &listenerCheckpoint{
		Block:            l.hwmBlock,
		TransactionIndex: -1,
		LogIndex:         -1,
	}
}

func (l *listener) moveHWM(hwmBlock int64) {
	l.hwmMux.Lock()
	defer l.hwmMux.Unlock()
	if hwmBlock > l.hwmBlock {
		l.hwmBlock = hwmBlock
	}
}

// listenerCatchupLoop reads pages of blocks at a time, until it gets within the configured catchup-threshold
// of the head of the blockchain.
// Then it moves this listener into the head-set of listeners, which share a common filter, listening
// for new events to arrive at the head of the chain.
func (l *listener) listenerCatchupLoop() {
	defer close(l.catchupLoopDone)

	// Only filtering on a single listener
	ctx := log.WithLogField(l.es.ctx, "listener", l.id.String())
	al := l.es.buildAggregatedListener([]*listener{l})

	failCount := 0
	for {
		if l.c.doFailureDelay(ctx, failCount) {
			log.L(ctx).Debugf("Listener catchup loop loop exiting")
			return
		}

		readyForLead, removed := l.checkReadyForLeadPackOrRemoved(ctx)
		if removed {
			log.L(ctx).Infof("Listener removed during catchup")
			return
		}
		if readyForLead {
			// We're done with catchup for this listener - it can join the main group
			l.es.rejoinLeadGroup(l)
			log.L(ctx).Infof("Listener completed catchup, and rejoined lead group")
			return
		}

		fromBlock := l.hwmBlock
		toBlock := l.hwmBlock + l.c.catchupPageSize - 1
		events, err := l.es.getBlockRangeEvents(ctx, al, fromBlock, toBlock)
		if err != nil {
			if l.c.catchupDownscaleRegex.String() != "" && l.c.catchupDownscaleRegex.MatchString(err.Error()) {
				log.L(ctx).Warnf("Failed to query block range fromBlock=%d toBlock=%d. Error %s matches configured downscale regex, catchup page size will automatically be reduced", fromBlock, toBlock, err.Error())
				if l.c.catchupPageSize > 1 {
					l.c.catchupPageSize /= 2

					if l.c.catchupPageSize < 20 {
						log.L(ctx).Warnf("Catchup page size auto-reduced to extremely low value %d. The connector may never catch up with the head of the chain.", l.c.catchupPageSize)
					}
				}
			} else {
				log.L(ctx).Errorf("Failed to query block range fromBlock=%d toBlock=%d: %s", fromBlock, toBlock, err)
				failCount++
			}
			continue
		}
		log.L(ctx).Infof("Listener catchup fromBlock=%d toBlock=%d events=%d", fromBlock, toBlock, len(events))

		for _, event := range events {
			log.L(ctx).Debugf("Detected event %s (listener catchup)", event.Event)
			select {
			case l.es.events <- event:
			case <-l.es.ctx.Done():
				log.L(ctx).Infof("Listener catchup loop exiting as stream is stopping")
				return
			}
		}
		l.hwmMux.Lock()
		l.hwmBlock = toBlock + 1
		l.hwmMux.Unlock()
		failCount = 0 // Reset on success
	}
}

func (l *listener) decodeLogData(ctx context.Context, event *abi.Entry, topics []ethtypes.HexBytes0xPrefix, data ethtypes.HexBytes0xPrefix) *fftypes.JSONAny {
	var b []byte
	v, err := event.DecodeEventDataCtx(ctx, topics, data)
	if err == nil {
		b, err = l.c.serializer.SerializeJSONCtx(ctx, v)
	}
	if err != nil {
		log.L(ctx).Errorf("Failed to process event log: %s", err)
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
		if bytes.Equal(m.FunctionSelectorBytes(), functionID) {
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
	var b []byte
	if err == nil {
		b, err = l.c.serializer.SerializeJSONCtx(ctx, v)
	}
	if err != nil {
		log.L(ctx).Warnf("Failed to decode input for TX '%s' using '%s'", txInfo.Hash, info.InputMethod)
		return
	}
	info.InputArgs = fftypes.JSONAnyPtrBytes(b)
}

func (l *listener) filterEnrichEthLog(ctx context.Context, f *eventFilter, ethLog *logJSONRPC) (*ffcapi.ListenerEvent, bool, error) {

	// Check the block for this event is at our high water mark, as we might have rewound for other listeners
	blockNumber := ethLog.BlockNumber.BigInt().Int64()
	transactionIndex := ethLog.TransactionIndex.BigInt().Int64()
	logIndex := ethLog.LogIndex.BigInt().Int64()
	protoID := getEventProtoID(blockNumber, transactionIndex, logIndex)
	if blockNumber < l.hwmBlock {
		log.L(ctx).Debugf("Listener %s already delivered event '%s' hwm=%d", l.id, protoID, l.hwmBlock)
		return nil, false, nil
	}

	// Apply a post-filter check to the event
	topicMatches := len(ethLog.Topics) > 0 && bytes.Equal(ethLog.Topics[0], f.Topic0)
	addrMatches := f.Address == nil || bytes.Equal(ethLog.Address[:], f.Address[:])
	if !topicMatches || !addrMatches {
		log.L(ctx).Debugf("Listener %s skipping event '%s' topicMatches=%t addrMatches=%t", l.id, protoID, topicMatches, addrMatches)
		return nil, false, nil
	}

	log.L(ctx).Infof("Listener %s detected event '%s'", l.id, protoID)
	data := l.decodeLogData(ctx, f.Event, ethLog.Topics, ethLog.Data)

	info := eventInfo{
		logJSONRPC: *ethLog,
	}

	var timestamp *fftypes.FFTime
	if l.c.eventBlockTimestamps {
		bi, err := l.c.getBlockInfoByHash(ctx, ethLog.BlockHash.String())
		if bi == nil || err != nil {
			log.L(ctx).Errorf("Failed to get block info timestamp for block '%s': %v", ethLog.BlockHash, err)
			return nil, false, err // This is an error condition, rather than just something we cannot enrich
		}
		timestamp = fftypes.UnixTime(bi.Timestamp.BigInt().Int64())
	}

	if len(l.config.options.Methods) > 0 || l.config.options.Signer {
		txInfo, err := l.c.getTransactionInfo(ctx, ethLog.TransactionHash)
		if txInfo == nil || err != nil {
			if txInfo == nil {
				log.L(ctx).Errorf("Failed to get transaction info for TX '%s': transaction hash not found", ethLog.TransactionHash)
			} else {
				log.L(ctx).Errorf("Failed to get transaction info for TX '%s': %v", ethLog.TransactionHash, err)
			}
			return nil, false, err // This is an error condition, rather than just something we cannot enrich
		}
		if l.config.options.Signer {
			info.InputSigner = txInfo.From
		}
		if len(l.config.options.Methods) > 0 {
			l.matchMethod(ctx, l.config.options.Methods, txInfo, &info)
		}
	}

	signature := f.Signature
	return &ffcapi.ListenerEvent{
		Checkpoint: &listenerCheckpoint{
			Block:            blockNumber,
			TransactionIndex: transactionIndex,
			LogIndex:         logIndex,
		},
		Event: &ffcapi.Event{
			ID: ffcapi.EventID{
				ListenerID:       l.id,
				Signature:        signature,
				BlockHash:        ethLog.BlockHash.String(),
				TransactionHash:  ethLog.TransactionHash.String(),
				BlockNumber:      fftypes.FFuint64(blockNumber),
				TransactionIndex: fftypes.FFuint64(transactionIndex),
				LogIndex:         fftypes.FFuint64(logIndex),
				Timestamp:        timestamp,
			},
			Info: &info,
			Data: data,
		},
	}, true, nil
}
