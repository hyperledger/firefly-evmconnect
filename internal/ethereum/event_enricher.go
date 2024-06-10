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

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

type eventEnricher struct {
	connector     *ethConnector
	methods       []*abi.Entry
	extractSigner bool
}

func (ee *eventEnricher) filterEnrichEthLog(ctx context.Context, f *eventFilter, ethLog *logJSONRPC) (*ffcapi.Event, bool, error) {

	// Check the block for this event is at our high water mark, as we might have rewound for other listeners
	blockNumber := ethLog.BlockNumber.BigInt().Int64()
	transactionIndex := ethLog.TransactionIndex.BigInt().Int64()
	logIndex := ethLog.LogIndex.BigInt().Int64()
	protoID := getEventProtoID(blockNumber, transactionIndex, logIndex)

	// Apply a post-filter check to the event
	topicMatches := len(ethLog.Topics) > 0 && bytes.Equal(ethLog.Topics[0], f.Topic0)
	addrMatches := f.Address == nil || bytes.Equal(ethLog.Address[:], f.Address[:])
	if !topicMatches || !addrMatches {
		log.L(ctx).Debugf("skipping event '%s' topicMatches=%t addrMatches=%t", protoID, topicMatches, addrMatches)
		return nil, false, nil
	}

	log.L(ctx).Infof("detected event '%s'", protoID)
	data := ee.decodeLogData(ctx, f.Event, ethLog.Topics, ethLog.Data)

	info := eventInfo{
		logJSONRPC: *ethLog,
	}

	var timestamp *fftypes.FFTime
	if ee.connector.eventBlockTimestamps {
		bi, err := ee.connector.getBlockInfoByHash(ctx, ethLog.BlockHash.String())
		if bi == nil || err != nil {
			log.L(ctx).Errorf("Failed to get block info timestamp for block '%s': %v", ethLog.BlockHash, err)
			return nil, false, err // This is an error condition, rather than just something we cannot enrich
		}
		timestamp = fftypes.UnixTime(bi.Timestamp.BigInt().Int64())
	}

	if len(ee.methods) > 0 || ee.extractSigner {
		txInfo, err := ee.connector.getTransactionInfo(ctx, ethLog.TransactionHash)
		if txInfo == nil || err != nil {
			if txInfo == nil {
				log.L(ctx).Errorf("Failed to get transaction info for TX '%s': transaction hash not found", ethLog.TransactionHash)
			} else {
				log.L(ctx).Errorf("Failed to get transaction info for TX '%s': %v", ethLog.TransactionHash, err)
			}
			return nil, false, err // This is an error condition, rather than just something we cannot enrich
		}
		if ee.extractSigner {
			info.InputSigner = txInfo.From
		}
		if len(ee.methods) > 0 {
			ee.matchMethod(ctx, ee.methods, txInfo, &info)
		}
	}

	signature := f.Signature
	return &ffcapi.Event{
		ID: ffcapi.EventID{
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
	}, true, nil
}

func (ee *eventEnricher) decodeLogData(ctx context.Context, event *abi.Entry, topics []ethtypes.HexBytes0xPrefix, data ethtypes.HexBytes0xPrefix) *fftypes.JSONAny {
	var b []byte
	v, err := event.DecodeEventDataCtx(ctx, topics, data)
	if err == nil {
		b, err = ee.connector.serializer.SerializeJSONCtx(ctx, v)
	}
	if err != nil {
		log.L(ctx).Errorf("Failed to process event log: %s", err)
		return nil
	}
	return fftypes.JSONAnyPtrBytes(b)
}

func (ee *eventEnricher) matchMethod(ctx context.Context, methods []*abi.Entry, txInfo *txInfoJSONRPC, info *eventInfo) {
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
		b, err = ee.connector.serializer.SerializeJSONCtx(ctx, v)
	}
	if err != nil {
		log.L(ctx).Warnf("Failed to decode input for TX '%s' using '%s'", txInfo.Hash, info.InputMethod)
		return
	}
	info.InputArgs = fftypes.JSONAnyPtrBytes(b)
}
