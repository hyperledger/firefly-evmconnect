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

// eventStream is the state we hold in memory for each eventStream
type eventStream struct {
	id             *fftypes.UUID
	ctx            context.Context
	c              *ethConnector
	events         chan<- *ffcapi.ListenerEvent
	mux            sync.Mutex
	updateCount    int
	listeners      map[fftypes.UUID]*listener
	headBlock      int64
	streamLoopDone chan struct{}
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

func parseEventFilters(ctx context.Context, filters []fftypes.JSONAny) (string, []*eventFilter, error) {
	if len(filters) < 1 {
		return "", nil, i18n.NewError(ctx, msgs.MsgMissingEventFilter)
	}
	ethFilters := make([]*eventFilter, len(filters))
	sigStrings := make([]string, len(filters))
	for i, f := range filters {
		err := json.Unmarshal(f.Bytes(), &ethFilters[i])
		if err != nil {
			return "", nil, i18n.NewError(ctx, msgs.MsgInvalidEventFilter, f.Bytes())
		}
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

func (es *eventStream) addEventListener(ctx context.Context, req *ffcapi.EventListenerAddRequest) (*listener, error) {
	es.mux.Lock()
	defer es.mux.Unlock()
	_, ok := es.listeners[*req.ListenerID]
	if ok {
		return nil, i18n.NewError(ctx, msgs.MsgListenerAlreadyStarted, req.ListenerID)
	}

	var checkpoint *listenerCheckpoint
	if req.Checkpoint != nil {
		checkpoint = req.Checkpoint.(*listenerCheckpoint)
	}

	signature, filters, err := parseEventFilters(ctx, req.Filters)
	if err != nil || req.Options == nil {
		// Should not happen as we've previously been called with EventListenerVerifyOptions
		return nil, i18n.NewError(ctx, msgs.MsgInvalidListenerOptions, err)
	}

	options, err := parseListenerOptions(ctx, req.Options)
	if err != nil {
		return nil, err
	}

	l := &listener{
		id:       req.ListenerID,
		c:        es.c,
		es:       es,
		hwmBlock: -1,
		config: listenerConfig{
			name:      req.Name,
			fromBlock: req.FromBlock,
			options:   options,
			filters:   filters,
			signature: signature,
		},
	}
	if checkpoint != nil {
		l.hwmBlock = checkpoint.Block
	}
	if err := l.ensureHWM(ctx); err != nil {
		return nil, err
	}

	es.updateCount++
	es.listeners[*req.ListenerID] = l

	return l, nil
}

func (es *eventStream) startEventListener(l *listener) {
	readyForLead, removed := l.checkReadyForLeadPackOrRemoved(es.ctx)
	l.catchup = !readyForLead
	if l.catchup && !removed {
		l.catchupLoopDone = make(chan struct{})
		go l.listenerCatchupLoop()
	}
}

func (es *eventStream) removeEventListener(listenerID *fftypes.UUID) {
	es.mux.Lock()
	defer es.mux.Unlock()

	l := es.listeners[*listenerID]
	if l != nil {
		es.updateCount++
		delete(es.listeners, *listenerID)
		l.hwmMux.Lock()
		l.removed = true
		l.hwmMux.Unlock()
		log.L(es.ctx).Infof("Listener '%s' removed", listenerID)
	}
}

func (es *eventStream) rejoinLeadGroup(l *listener) {
	l.es.mux.Lock()
	defer l.es.mux.Unlock()
	l.es.updateCount++
	l.catchup = false
}

func (es *eventStream) buildReuseLeadGroupListener(lastUpdate *int, ag **aggregatedListener) bool {
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
		*ag = es.buildAggregatedListener(listeners)
		listenerChanged = true
		*lastUpdate = es.updateCount
	}
	return listenerChanged
}

// leadGroupCatchup is called whenever the steam loop restarts, to see how far it is behind the head of the
// chain and if it's a way behind then we catch up all this head group as one set (rather than with individual
// catchup routines as is the case if one listener starts a way behind the pack)
func (es *eventStream) leadGroupCatchup() {

	var ag *aggregatedListener
	lastUpdate := -1
	retryCount := 0
	for {
		chainHeadBlock := es.c.blockListener.getHighestBlock(es.ctx)

		// Build the aggregated listener list (doesn't matter if it's changed, as we build the list each time)
		_ = es.buildReuseLeadGroupListener(&lastUpdate, &ag)

		// Determine the earliest block we need to poll from
		fromBlock := int64(-1)
		for _, l := range ag.listeners {
			if fromBlock < 0 || l.hwmBlock < fromBlock {
				fromBlock = l.hwmBlock
			}
		}

		// Check if we're ready to exit catchup mode
		headGap := (chainHeadBlock - fromBlock)
		if headGap < es.c.catchupThreshold {
			log.L(es.ctx).Infof("Stream head is up to date with chain fromBlock=%d chainHead=%d headGap=%d", fromBlock, chainHeadBlock, headGap)
			return
		}

		// Poll in the range for events
		toBlock := fromBlock + es.c.catchupPageSize - 1
		events, err := es.getBlockRangeEvents(es.ctx, ag, fromBlock, toBlock)
		if err != nil {
			es.c.doDelay(es.ctx, &retryCount, err)
			continue
		}
		log.L(es.ctx).Infof("Stream catchup fromBlock=%d toBlock=%d headBlock=%d events=%d listeners=%d", fromBlock, toBlock, chainHeadBlock, len(events), len(ag.listeners))

		// Dispatch the events
		if es.dispatchSetHWMCheckExit(ag, events, toBlock+1 /* hwm is the next block after our poll */) {
			log.L(es.ctx).Debugf("Stream catchup loop exiting")
			return
		}

		// Reset retry count for a successful loop
		retryCount = 0
	}

}

func (es *eventStream) streamLoop() {
	defer close(es.streamLoopDone)

	// When we first start, we might find our leading pack of listeners are all way behind
	// the head of the chain. So we run a catchup mode loop to ensure we don't ask the blockchain
	// node to process an excessive amount of logs
	es.leadGroupCatchup()

	var filter *ethtypes.HexInteger
	uninstallFilter := func() {
		var res bool
		if err := es.c.backend.Invoke(es.ctx, &res, "eth_uninstallFilter", filter); err != nil {
			log.L(es.ctx).Warnf("Error uninstalling filter '%s': %s", filter, err)
		}
		filter = nil
	}
	defer uninstallFilter()

	// Then we move into the head mode, where we establish a long-lived filter, and keep polling for changes on it.
	retryCount := 0
	filterRPC := ""
	lastUpdate := -1
	var ag *aggregatedListener
	for {
		// Build the aggregated listener list if it has changed
		listenerChanged := es.buildReuseLeadGroupListener(&lastUpdate, &ag)

		// No need to poll for events, if we don't have any listeners
		if len(ag.signatureSet) > 0 {
			// High water mark is a point safely behind the head of the chain in this case,
			// where re-orgs are not expected.
			hwmBlock := es.c.blockListener.getHighestBlock(es.ctx) - es.c.checkpointBlockGap

			// Re-establish the filter if we need to
			if filter == nil || listenerChanged {
				// Uninstall any existing filter
				if filter != nil {
					uninstallFilter()
				}
				filterRPC = "eth_getFilterLogs" // first JSON/RPC after getting a new
				// Determine the earliest block we need to poll from
				fromBlock := int64(-1)
				for _, l := range ag.listeners {
					if fromBlock < 0 || l.hwmBlock < fromBlock {
						fromBlock = l.hwmBlock
					}
				}
				// Create the new filter
				err := es.c.backend.Invoke(es.ctx, &filter, "eth_newFilter", &logFilterJSONRPC{
					FromBlock: ethtypes.NewHexInteger64(fromBlock),
					Topics: [][]ethtypes.HexBytes0xPrefix{
						ag.signatureSet,
					},
				})
				// If we fail to create the filter, we need to keep retrying
				if err != nil {
					es.c.doDelay(es.ctx, &retryCount, err)
					continue
				}
				log.L(es.ctx).Infof("Filter '%s' established", filter)
			}
			// Get the next batch of logs
			var ethLogs []*logJSONRPC
			err := es.c.backend.Invoke(es.ctx, &ethLogs, filterRPC, filter)
			// If we fail to query we just retry - setting filter to nil if not found
			if err != nil {
				if mapError(filterRPCMethods, err) == ffcapi.ErrorReasonNotFound {
					log.L(es.ctx).Infof("Filter '%s' reset: %s", filter, err)
					filter = nil
				}
				es.c.doDelay(es.ctx, &retryCount, err)
				continue
			}

			// Enrich the events
			events, err := es.filterEnrichSort(es.ctx, ag, ethLogs)
			if err != nil {
				es.c.doDelay(es.ctx, &retryCount, err)
				continue
			}

			// Dispatch the events
			if es.dispatchSetHWMCheckExit(ag, events, hwmBlock) {
				log.L(es.ctx).Debugf("Stream loop exiting")
				return
			}

			// Update the head block to be the hwm block
			es.mux.Lock()
			es.headBlock = hwmBlock
			es.mux.Unlock()
		}

		// Sleep for the polling interval
		select {
		case <-time.After(es.c.eventFilterPollingInterval):
		case <-es.ctx.Done():
			log.L(es.ctx).Debugf("Stream loop stopping")
			return
		}
	}
}

func (es *eventStream) dispatchSetHWMCheckExit(ag *aggregatedListener, events ffcapi.ListenerEvents, hwm int64) (exiting bool) {

	// Dispatch the events, updating the in-memory checkpoint for all listeners.
	if len(events) == 0 {
		select {
		case <-es.ctx.Done():
			return true
		default:
		}
	}
	for _, event := range events {
		select {
		case es.events <- event:
		case <-es.ctx.Done():
			return true
		}
	}

	// Set the HWM on all the listeners
	for _, l := range ag.listeners {
		l.setHWM(hwm)
	}

	return false

}

func (es *eventStream) buildAggregatedListener(listeners []*listener) *aggregatedListener {
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

func getEventProtoID(blockNumber, transactionIndex, logIndex int64) string {
	return fmt.Sprintf("%.12d/%.6d/%.6d", blockNumber, transactionIndex, logIndex)
}

func (es *eventStream) filterEnrichSort(ctx context.Context, ag *aggregatedListener, ethLogs []*logJSONRPC) (ffcapi.ListenerEvents, error) {
	updates := make(ffcapi.ListenerEvents, 0, len(ethLogs))
	for _, ethLog := range ethLogs {
		listeners := ag.listenersByTopic0[ethLog.Topics[0].String()]
		for _, l := range listeners {
			for _, f := range l.config.filters {
				lu, matches := l.filterEnrichEthLog(ctx, f, ethLog)
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

func (es *eventStream) getBlockRangeEvents(ctx context.Context, ag *aggregatedListener, fromBlock, toBlock int64) (ffcapi.ListenerEvents, error) {

	if len(ag.signatureSet) == 0 {
		return nil, nil
	}

	var ethLogs []*logJSONRPC
	err := es.c.backend.Invoke(ctx, &ethLogs, "eth_getLogs", &logFilterJSONRPC{
		FromBlock: ethtypes.NewHexInteger64(fromBlock),
		ToBlock:   ethtypes.NewHexInteger64(toBlock),
		Topics: [][]ethtypes.HexBytes0xPrefix{
			ag.signatureSet,
		},
	})
	if err != nil {
		return nil, err
	}

	return es.filterEnrichSort(ctx, ag, ethLogs)
}

func (es *eventStream) getListenerHWM(ctx context.Context, listenerID *fftypes.UUID) (*ffcapi.EventListenerHWMResponse, ffcapi.ErrorReason, error) {
	es.mux.Lock()
	l := es.listeners[*listenerID]
	es.mux.Unlock()
	if l == nil {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgListenerNotStarted, listenerID, es.id)
	}
	return &ffcapi.EventListenerHWMResponse{
		Checkpoint: l.getHWMCheckpoint(),
	}, "", nil
}
