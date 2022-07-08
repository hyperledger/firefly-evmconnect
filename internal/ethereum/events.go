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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

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

// eventFilter is our Ethereum specific filter options - an array of these can be configured on each listener
type eventFilter struct {
	Event   *abi.Entry                `json:"event"`             // The ABI spec of the event to listen to
	Address *ethtypes.Address0xHex    `json:"address,omitempty"` // An optional address to restrict the
	Topic0  ethtypes.HexBytes0xPrefix `json:"topic0"`            // Topic 0 match
}

// eventInfo is the top-level structure we pass to applications for each event (through the FFCAPI framework)
type eventInfo struct {
	logJSONRPC
	DeprecatedSubID *fftypes.UUID          `json:"subId"`                 // ID of the listener - deprecated "subscription" naming
	ListenerID      *fftypes.UUID          `json:"listenerId"`            // ID of the listener
	ListenerName    string                 `json:"listenerName"`          // name of the listener
	Signature       string                 `json:"signature"`             // event signature string
	Timestamp       uint64                 `json:"timestamp,omitempty"`   // block timestamp, if enabled in the configuration
	InputMethod     string                 `json:"inputMethod,omitempty"` // the method invoked, if it matched one of the signatures in the listener definition
	InputArgs       *fftypes.JSONAny       `json:"inputArgs,omitempty"`   // the method parameters, if the method matched one of the signatures in the listener definition
	InputSigner     *ethtypes.Address0xHex `json:"inputSigner,omitempty"` // the signing `from` address of the transaction
}

// listenerConfig is the configuration parsed from generic FFCAPI connector framework JSON, into our Ethereum specific options
type listenerConfig struct {
	name      string
	fromBlock string
	options   *listenerOptions
	filters   []*eventFilter
	signature string
}

// eventStream is the state we hold in memory for each eventStream
type eventStream struct {
	id          *fftypes.UUID
	ctx         context.Context
	events      chan<- *ffcapi.ListenerEvent
	mux         sync.Mutex
	updateCount int
	listeners   map[fftypes.UUID]*listener
	headBlock   int64
}

// listener is the state we hold in memory for each individual listener that has been added
type listener struct {
	id            *fftypes.UUID
	eventStream   *eventStream
	checkpointMux sync.Mutex // Protects checkpoint of an individual listener. May hold ES lock when taking this, must NOT attempt to obtain ES lock while holding this
	checkpoint    *listenerCheckpoint
	config        listenerConfig
	catchup       bool
}

// aggregatedListener is a generated structure that allows use to query/filter logs efficiently across a large number of listeners,
// while minimizing the number of JSON/RPC calls we need to make to the node/gateway.  This is very important when dealing with an
// industrial scale of listeners, that might share event signatures. For example listening to 1000 different "transfer" events for
// different contract addresses.
type aggregatedListener struct {
	signatureSet      []ethtypes.HexBytes0xPrefix // a list of unique topic[0] event signatures to listener for
	listenersByTopic0 map[string][]*listener      // a map of all listeners that are interested in an event signature - they may not be interested in the event itself (depending on sub-selection)
	listeners         []*listener                 // list of all listeners
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

func (c *ethConnector) getInitialBlock(ctx context.Context, fromBlockInstruction string) (int64, error) {
	if fromBlockInstruction == ffcapi.FromBlockLatest || fromBlockInstruction == "" {
		// Get the latest block number to store in the `FromBlock`
		var fromBlock *fftypes.FFBigInt
		err := c.backend.Invoke(ctx, &fromBlock, "eth_blockNumber")
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

func (c *ethConnector) parseEventFilters(ctx context.Context, filters []fftypes.JSONAny) (string, []*eventFilter, error) {
	if len(filters) < 1 {
		return "", nil, i18n.NewError(ctx, msgs.MsgMissingEventFilter)
	}
	ethFilters := make([]*eventFilter, len(filters))
	sigStrings := make([]string, len(filters))
	for i, f := range filters {
		err := json.Unmarshal(f.Bytes(), &ethFilters[i])
		if ethFilters[i].Event == nil {
			return "", nil, i18n.NewError(ctx, msgs.MsgMissingEventFilter)
		}
		if err == nil {
			ethFilters[i].Topic0, err = ethFilters[i].Event.SignatureHashCtx(ctx)
		}
		if err != nil {
			return "", nil, i18n.NewError(ctx, msgs.MsgInvalidEventFilter, err)
		}
		if ethFilters[i].Address != nil {
			sigStrings[i] = ethFilters[i].Address.String() + ":" + ethFilters[i].Event.String()
		} else {
			sigStrings[i] = "*:" + ethFilters[i].Event.String()
		}
	}
	var signature string
	if len(sigStrings) == 1 {
		signature = sigStrings[0]
	} else {
		signature = "[" + strings.Join(sigStrings, ",") + "]"
	}
	return signature, ethFilters, nil
}

func (c *ethConnector) parseOptions(ctx context.Context, o *fftypes.JSONAny) (*listenerOptions, error) {
	var options listenerOptions
	if o != nil {
		err := json.Unmarshal(o.Bytes(), &options)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgInvalidListenerOptions, err)
		}
	}
	return &options, nil
}

func (c *ethConnector) EventStreamStart(ctx context.Context, req *ffcapi.EventStreamStartRequest) (*ffcapi.EventStreamStartResponse, ffcapi.ErrorReason, error) {
	c.mux.Lock()
	defer c.mux.Unlock()
	es := c.eventStreams[*req.ID]
	if es != nil {
		return nil, ffcapi.ErrorReason(""), i18n.NewError(ctx, msgs.MsgStreamAlreadyStarted, req.ID)
	}

	es = &eventStream{
		id:        req.ID,
		ctx:       req.StreamContext,
		events:    req.EventStream,
		headBlock: -1,
		listeners: make(map[fftypes.UUID]*listener),
	}
	for _, lReq := range req.InitialListeners {
		l, err := c.addEventListener(ctx, es, lReq)
		if err != nil {
			return nil, "", err
		}
		// During initial start we move the "head" block forwards to be the highest of all the initial streams
		if l.checkpoint.Block > es.headBlock {
			es.headBlock = l.checkpoint.Block
		}
	}

	// Now we've calculated our head block, go through and start all the listeners - which might kick off catchup on some of them
	for _, l := range es.listeners {
		c.startEventListener(ctx, l)
	}

	// Finally start the listener head routine, which reads events for all listeners that are not in catchup mode
	go c.streamLoop(es)

	return nil, "", nil
}

func (c *ethConnector) EventListenerVerifyOptions(ctx context.Context, req *ffcapi.EventListenerVerifyOptionsRequest) (*ffcapi.EventListenerVerifyOptionsResponse, ffcapi.ErrorReason, error) {

	signature, _, err := c.parseEventFilters(ctx, req.Filters)
	if err != nil {
		return nil, "", err
	}

	options, err := c.parseOptions(ctx, req.Options)
	if err != nil {
		return nil, "", err
	}

	ob, _ := json.Marshal(&options)
	return &ffcapi.EventListenerVerifyOptionsResponse{
		ResolvedSignature: signature,
		ResolvedOptions:   fftypes.JSONAny(ob),
	}, "", nil

}

func (c *ethConnector) EventListenerAdd(ctx context.Context, req *ffcapi.EventListenerAddRequest) (*ffcapi.EventListenerAddResponse, ffcapi.ErrorReason, error) {
	c.mux.Lock()
	es := c.eventStreams[*req.StreamID]
	c.mux.Unlock()
	if es == nil {
		return nil, ffcapi.ErrorReason(""), i18n.NewError(ctx, msgs.MsgStreamNotStarted, req.StreamID)
	}
	l, err := c.addEventListener(ctx, es, req)
	if err != nil {
		return nil, ffcapi.ErrorReason(""), err
	}
	// We start this listener straight away
	c.startEventListener(ctx, l)
	return &ffcapi.EventListenerAddResponse{}, ffcapi.ErrorReason(""), nil
}

func (c *ethConnector) addEventListener(ctx context.Context, es *eventStream, req *ffcapi.EventListenerAddRequest) (*listener, error) {
	es.mux.Lock()
	defer es.mux.Unlock()
	_, ok := es.listeners[*req.ID]
	if ok {
		return nil, i18n.NewError(ctx, msgs.MsgListenerAlreadyStarted, req.ID)
	}

	var checkpoint *listenerCheckpoint
	if req.Checkpoint != nil {
		if err := json.Unmarshal(req.Checkpoint.Bytes(), &checkpoint); err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgInvalidCheckpoint, err)
		}
	}

	signature, filters, err := c.parseEventFilters(ctx, req.Filters)
	if err != nil || req.Options == nil {
		// Should not happen as we've previously been called with EventListenerVerifyOptions
		return nil, i18n.NewError(ctx, msgs.MsgInvalidListenerOptions, err)
	}

	options, err := c.parseOptions(ctx, req.Options)
	if err != nil {
		return nil, err
	}

	l := &listener{
		id:          req.ID,
		eventStream: es,
		checkpoint:  checkpoint,
		config: listenerConfig{
			name:      req.Name,
			fromBlock: req.FromBlock,
			options:   options,
			filters:   filters,
			signature: signature,
		},
	}
	if err := c.ensureCheckpoint(ctx, l); err != nil {
		return nil, err
	}
	es.listeners[*req.ID] = l

	return l, nil
}

func (c *ethConnector) startEventListener(ctx context.Context, l *listener) {
	// If the block gap at the point of start is
	if c.checkCatchup(ctx, l) {
		go c.listenerCatchupLoop(l)
	}
}

func (c *ethConnector) EventListenerRemove(ctx context.Context, req *ffcapi.EventListenerRemoveRequest) (*ffcapi.EventListenerRemoveResponse, ffcapi.ErrorReason, error) {
	return nil, "", nil
}

func (c *ethConnector) EventListenerHWM(ctx context.Context, req *ffcapi.EventListenerHWMRequest) (*ffcapi.EventListenerHWMResponse, ffcapi.ErrorReason, error) {
	return nil, "", nil
}

func (c *ethConnector) NewBlockHashes() <-chan *ffcapi.BlockHashEvent {
	return nil
}

func (c *ethConnector) doDelay(ctx context.Context, retryCount *int, err error) bool {
	retryDelay := c.retry.InitialDelay
	for i := 0; i < *retryCount; i++ {
		retryDelay = time.Duration(float64(retryDelay) * c.retry.Factor)
		if retryDelay > c.retry.MaximumDelay {
			retryDelay = c.retry.MaximumDelay
			break
		}
	}
	log.L(ctx).Errorf("Retrying after %.2s for error (retries=%d): %s", retryDelay.Seconds(), retryCount, err)
	*retryCount++
	select {
	case <-time.After(retryDelay):
		return false
	case <-ctx.Done():
		return true
	}
}

func (c *ethConnector) ensureCheckpoint(ctx context.Context, l *listener) error {
	l.checkpointMux.Lock()
	defer l.checkpointMux.Unlock()
	if l.checkpoint == nil {
		firstBlock, err := c.getInitialBlock(ctx, l.config.fromBlock)
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

func (c *ethConnector) checkCatchup(ctx context.Context, l *listener) bool {
	l.checkpointMux.Lock()
	defer l.checkpointMux.Unlock()
	// We do a dirty read of the head block (unless the caller has locked the eventStream Mutex, which
	// we support in the mutex hierarchy)
	headBlock := l.eventStream.headBlock
	blockGap := headBlock - l.checkpoint.Block
	l.catchup = blockGap > c.catchupThreshold
	log.L(ctx).Debugf("Listener %s catchup=%t head=%d gap=%d", l.catchup, headBlock, blockGap)
	return l.catchup
}

// leadGroupCatchup is called whenever the steam loop restarts, to see how far it is behind the head of the
// chain and if it's
func (c *ethConnector) leadGroupCatchup() {

	//

}

// listenerCatchupLoop reads pages of blocks at a time, until it gets within the configured catchup-threshold
// of the head of the blockchain.
// Then it moves this listener into the head-set of listeners, which share a common filter, listening
// for new events to arrive at the head of the chain.
func (c *ethConnector) listenerCatchupLoop(l *listener) {

	// Only filtering on a single listener
	ctx := log.WithLogField(l.eventStream.ctx, "listener", l.id.String())
	al := c.buildAggregatedListener([]*listener{l})

	retryCount := 0
	for {
		if !c.checkCatchup(ctx, l) {
			// We're done with catchup for this listener - it can join the main group
			c.rejoinLeadGroup(l)
			log.L(ctx).Infof("Listener completed catchup, and rejoined lead group")
			return
		}

		fromBlock := l.checkpoint.Block
		toBlock := l.checkpoint.Block + c.catchupPageSize
		events, err := c.getBlockRangeEvents(ctx, al, fromBlock, toBlock)
		if err != nil {
			if c.doDelay(l.eventStream.ctx, &retryCount, err) {
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

func (c *ethConnector) rejoinLeadGroup(l *listener) {
	l.eventStream.mux.Lock()
	defer l.eventStream.mux.Unlock()
	l.eventStream.updateCount++
	l.catchup = false
}

func (c *ethConnector) getStreamListener(es *eventStream, lastUpdate *int, ag **aggregatedListener) bool {
	es.mux.Lock()
	defer es.mux.Unlock()
	listenerChanged := false
	if *lastUpdate != es.updateCount {
		listeners := make([]*listener, 0, len(es.listeners))
		for _, l := range es.listeners {
			if !l.catchup {
				listeners = append(listeners, l)
			}
		}
		*ag = c.buildAggregatedListener(listeners)
		listenerChanged = true
		*lastUpdate = es.updateCount
	}
	return listenerChanged
}

func (c *ethConnector) streamLoop(es *eventStream) {

	lastUpdate := -1
	var ag *aggregatedListener
	var filter *ethtypes.HexInteger

	// When we first start, we might find our leading pack of listeners are all way behind
	// the head of the chain. So we run a catchup mode loop to ensure we don't ask the blockchain
	// node to process an excessive amount of logs

	// Then we move into the head mode, where we establish a long-lived filter, and keep polling for changes on it.
	retryCount := 0
	filterRPC := ""
	for {
		// Build the aggregated listener list if it has changed
		listenerChanged := c.getStreamListener(es, &lastUpdate, &ag)

		// No need to poll for events, if we don't have any listeners
		if len(ag.signatureSet) > 0 {
			// Re-establish the filter if we need to
			if filter == nil || listenerChanged {
				// Uninstall any existing filter
				if filter != nil {
					var res bool
					if err := c.backend.Invoke(es.ctx, &res, "eth_newFilter", filter); err != nil {
						log.L(es.ctx).Warnf("Error uninstalling old filter: %s", err)
					}
					filter = nil
				}
				filterRPC = "eth_getFilterLogs" // first JSON/RPC after getting a new
				// Determine the earliest block we need to poll from
				fromBlock := int64(-1)
				for _, l := range ag.listeners {
					if fromBlock < 0 || l.checkpoint.Block < fromBlock {
						fromBlock = l.checkpoint.Block
					}
				}
				// Create the new filter
				err := c.backend.Invoke(es.ctx, &filter, "eth_newFilter", &logFilterJSONRPC{
					FromBlock: ethtypes.NewHexInteger64(fromBlock),
					Topics: [][]ethtypes.HexBytes0xPrefix{
						ag.signatureSet,
					},
				})
				// If we fail to create the filter, we need to keep retrying
				if err != nil {
					c.doDelay(es.ctx, &retryCount, err)
					continue
				}
				log.L(es.ctx).Infof("Filter '%s' established", filter)
			}
			// Get the next batch of logs
			var ethLogs []*logJSONRPC
			err := c.backend.Invoke(es.ctx, &ethLogs, filterRPC, filter)
			// If we fail to query we just retry - setting filter to nil if not found
			if err != nil {
				if mapError(filterRPCMethods, err) == ffcapi.ErrorReasonNotFound {
					log.L(es.ctx).Infof("Filter '%s' reset: %s", filter, err)
					filter = nil
				}
				c.doDelay(es.ctx, &retryCount, err)
				continue
			}
		}
	}
}

func (c *ethConnector) buildAggregatedListener(listeners []*listener) *aggregatedListener {
	ag := &aggregatedListener{
		listeners:         listeners,
		listenersByTopic0: make(map[string][]*listener),
	}
	for _, l := range listeners {
		for _, f := range l.config.filters {
			sigStr := f.Topic0.String()
			topicListeners, existing := ag.listenersByTopic0[sigStr]
			if !existing {
				ag.signatureSet = append(ag.signatureSet, f.Topic0)
			}
			ag.listenersByTopic0[sigStr] = append(topicListeners, l)
		}
	}
	return ag
}

func (c *ethConnector) decodeLogData(ctx context.Context, event *abi.Entry, topics []ethtypes.HexBytes0xPrefix, data ethtypes.HexBytes0xPrefix) *fftypes.JSONAny {
	v, err := event.DecodeEventDataCtx(ctx, topics, data)
	if err != nil {
		log.L(ctx).Errorf("Failed to decode event: %s", err)
		return nil
	}
	b, err := c.serializer.SerializeJSONCtx(ctx, v)
	if err != nil {
		log.L(ctx).Errorf("Failed to serialize event: %s", err)
		return nil
	}
	return fftypes.JSONAnyPtrBytes(b)
}

func (c *ethConnector) matchMethod(ctx context.Context, methods []*abi.Entry, txInfo *txInfoJSONRPC, info *eventInfo) {
	if len(txInfo.Input) < 4 {
		log.L(ctx).Debug("No function selector available for TX '%s'", txInfo.Hash)
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
	b, err := c.serializer.SerializeJSONCtx(ctx, v)
	if err != nil {
		log.L(ctx).Errorf("Failed to serialize function input arguments: %s", err)
		return
	}
	info.InputArgs = fftypes.JSONAnyPtrBytes(b)
	return
}

func (c *ethConnector) getProtoID(blockNumber, transactionIndex, logIndex int64) string {
	return fmt.Sprintf("%.12d/%.6d/%.6d", blockNumber, transactionIndex, logIndex)
}

func (c *ethConnector) filterEnrichEthLog(ctx context.Context, l *listener, f *eventFilter, ethLog *logJSONRPC) (*ffcapi.ListenerEvent, bool) {

	// Apply a post-filter check to the event
	blockNumber := ethLog.BlockNumber.Int64()
	transactionIndex := ethLog.TransactionIndex.Int64()
	logIndex := ethLog.LogIndex.Int64()
	protoID := c.getProtoID(blockNumber, transactionIndex, logIndex)
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
	data := c.decodeLogData(ctx, f.Event, ethLog.Topics, ethLog.Data)

	info := eventInfo{
		logJSONRPC:      *ethLog,
		DeprecatedSubID: l.id,
		ListenerID:      l.id,
		ListenerName:    l.config.name,
	}

	if c.eventBlockTimestamps {
		bi, err := c.getBlockInfoByHash(ctx, ethLog.BlockHash.String())
		if bi == nil || err != nil {
			log.L(ctx).Errorf("Failed to get block info timestamp for block '%s': %v", ethLog.BlockHash, err)
		} else {
			info.Timestamp = bi.Timestamp.BigInt().Uint64()
		}
	}

	if len(l.config.options.Methods) > 0 {
		txInfo, err := c.getTransactionInfo(ctx, ethLog.TransactionHash)
		if txInfo == nil || err != nil {
			log.L(ctx).Errorf("Failed to get transaction info for TX '%s': %v", ethLog.TransactionHash, err)
		} else {
			info.InputSigner = txInfo.From
			c.matchMethod(ctx, l.config.options.Methods, txInfo, &info)
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

func (c *ethConnector) filterEnrichSort(ctx context.Context, ag *aggregatedListener, ethLogs []*logJSONRPC) (ffcapi.ListenerEvents, error) {
	updates := make(ffcapi.ListenerEvents, 0, len(ethLogs))
	for _, ethLog := range ethLogs {
		listeners := ag.listenersByTopic0[ethLog.Topics[0].String()]
		for _, l := range listeners {
			for _, f := range l.config.filters {
				lu, matches := c.filterEnrichEthLog(ctx, l, f, ethLog)
				if matches {
					updates = append(updates, lu)
					break // A single listener cannot emit the event twice
				}
			}
		}
	}
	sort.Sort(updates)
	return updates, nil
}

func (c *ethConnector) getBlockRangeEvents(ctx context.Context, ag *aggregatedListener, fromBlock, toBlock int64) (ffcapi.ListenerEvents, error) {

	if len(ag.signatureSet) == 0 {
		return nil, nil
	}

	var ethLogs []*logJSONRPC
	err := c.backend.Invoke(ctx, &ethLogs, "eth_getLogs", &logFilterJSONRPC{
		FromBlock: ethtypes.NewHexInteger64(fromBlock),
		ToBlock:   ethtypes.NewHexInteger64(toBlock),
		Topics: [][]ethtypes.HexBytes0xPrefix{
			ag.signatureSet,
		},
	})
	if err != nil {
		return nil, err
	}

	return c.filterEnrichSort(ctx, ag, ethLogs)
}
