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

package ethrpc

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

// TxReceiptJSONRPC is the receipt obtained over JSON/RPC from the ethereum client, with gas used, logs and contract address
type TxReceiptJSONRPC struct {
	TransactionHash   ethtypes.HexBytes0xPrefix `json:"transactionHash"`
	TransactionIndex  *ethtypes.HexInteger      `json:"transactionIndex"`
	BlockHash         ethtypes.HexBytes0xPrefix `json:"blockHash"`
	BlockNumber       *ethtypes.HexInteger      `json:"blockNumber"`
	From              *ethtypes.Address0xHex    `json:"from"`
	To                *ethtypes.Address0xHex    `json:"to"`
	CumulativeGasUsed *ethtypes.HexInteger      `json:"cumulativeGasUsed"`
	EffectiveGasPrice *ethtypes.HexInteger      `json:"effectiveGasPrice"`
	GasUsed           *ethtypes.HexInteger      `json:"gasUsed"`
	ContractAddress   *ethtypes.Address0xHex    `json:"contractAddress"`
	Logs              []*LogJSONRPC             `json:"logs"`
	LogsBloom         ethtypes.HexBytes0xPrefix `json:"logsBloom"`
	Type              *ethtypes.HexInteger      `json:"type"`
	Status            *ethtypes.HexInteger      `json:"status"`
	RevertReason      ethtypes.HexBytes0xPrefix `json:"revertReason"`
}

func (txr *TxReceiptJSONRPC) MarshalFormat(ctx context.Context, format JSONFormatOptions, opts ...MarshalOption) (jb []byte, err error) {
	logsArray := make([]json.RawMessage, len(txr.Logs))
	for i, l := range txr.Logs {
		if err == nil {
			logsArray[i], err = l.MarshalFormat(ctx, format, opts...)
		}
	}
	if err == nil {
		jb, err = format.MarshalFormattedMap(ctx, map[string]any{
			"transactionHash":   ([]byte)(txr.TransactionHash),
			"transactionIndex":  (*big.Int)(txr.TransactionIndex),
			"blockHash":         ([]byte)(txr.BlockHash),
			"blockNumber":       (*big.Int)(txr.BlockNumber),
			"from":              (*[20]byte)(txr.From),
			"to":                (*[20]byte)(txr.To),
			"cumulativeGasUsed": (*big.Int)(txr.CumulativeGasUsed),
			"effectiveGasPrice": (*big.Int)(txr.EffectiveGasPrice),
			"gasUsed":           (*big.Int)(txr.GasUsed),
			"contractAddress":   (*[20]byte)(txr.ContractAddress),
			"logs":              logsArray,
			"logsBloom":         ([]byte)(txr.LogsBloom),
			"status":            (*big.Int)(txr.Status),
			"type":              (*big.Int)(txr.Type),
			"revertReason":      ([]byte)(txr.RevertReason),
		}, append(opts, MarshalOption{
			OmitNullFields: []string{"revertReason"},
		})...)
	}
	return jb, err
}

// TxInfoJSONRPC is the transaction info obtained over JSON/RPC from the ethereum client, with input data
type TxInfoJSONRPC struct {
	BlockHash        ethtypes.HexBytes0xPrefix `json:"blockHash"`   // null if pending
	BlockNumber      *ethtypes.HexInteger      `json:"blockNumber"` // null if pending
	ChainID          *ethtypes.HexInteger      `json:"chainId"`
	From             *ethtypes.Address0xHex    `json:"from"`
	Gas              *ethtypes.HexInteger      `json:"gas"`
	GasPrice         *ethtypes.HexInteger      `json:"gasPrice"`
	Hash             ethtypes.HexBytes0xPrefix `json:"hash"`
	Input            ethtypes.HexBytes0xPrefix `json:"input"`
	Nonce            *ethtypes.HexInteger      `json:"nonce"`
	To               *ethtypes.Address0xHex    `json:"to"`
	TransactionIndex *ethtypes.HexInteger      `json:"transactionIndex"` // null if pending
	Type             *ethtypes.HexInteger      `json:"type"`
	Value            *ethtypes.HexInteger      `json:"value"`
	V                *ethtypes.HexInteger      `json:"v"`
	R                *ethtypes.HexInteger      `json:"r"`
	S                *ethtypes.HexInteger      `json:"s"`
}

func (txi *TxInfoJSONRPC) MarshalFormat(ctx context.Context, format JSONFormatOptions, opts ...MarshalOption) (_ []byte, err error) {
	return format.MarshalFormattedMap(ctx, map[string]any{
		"blockHash":        ([]byte)(txi.BlockHash),
		"blockNumber":      (*big.Int)(txi.BlockNumber),
		"chainId":          (*big.Int)(txi.ChainID),
		"from":             (*[20]byte)(txi.From),
		"gas":              (*big.Int)(txi.Gas),
		"gasPrice":         (*big.Int)(txi.GasPrice),
		"hash":             ([]byte)(txi.Hash),
		"input":            ([]byte)(txi.Input),
		"nonce":            (*big.Int)(txi.Nonce),
		"to":               (*[20]byte)(txi.To),
		"transactionIndex": (*big.Int)(txi.TransactionIndex),
		"type":             (*big.Int)(txi.Type),
		"value":            (*big.Int)(txi.Value),
		"v":                (*big.Int)(txi.V),
		"r":                (*big.Int)(txi.R),
		"s":                (*big.Int)(txi.S),
	}, opts...)
}

type LogFilterJSONRPC struct {
	FromBlock *ethtypes.HexInteger          `json:"fromBlock,omitempty"`
	ToBlock   *ethtypes.HexInteger          `json:"toBlock,omitempty"`
	Address   *ethtypes.Address0xHex        `json:"address,omitempty"`
	Topics    [][]ethtypes.HexBytes0xPrefix `json:"topics,omitempty"`
}

type LogJSONRPC struct {
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

func (l *LogJSONRPC) MarshalFormat(ctx context.Context, format JSONFormatOptions, opts ...MarshalOption) (_ []byte, err error) {
	topicsArray := make([]any, len(l.Topics))
	for i, t := range l.Topics {
		topicsArray[i] = ([]byte)(t)
	}
	return format.MarshalFormattedMap(ctx, map[string]any{
		"removed":          l.Removed,
		"logIndex":         (*big.Int)(l.LogIndex),
		"transactionIndex": (*big.Int)(l.TransactionIndex),
		"blockNumber":      (*big.Int)(l.BlockNumber),
		"transactionHash":  ([]byte)(l.TransactionHash),
		"blockHash":        ([]byte)(l.BlockHash),
		"address":          (*[20]byte)(l.Address),
		"data":             ([]byte)(l.Data),
		"topics":           topicsArray,
	}, opts...)
}

// BlockInfoJSONRPC are the info fields we parse from the JSON/RPC response, and cache
type BlockInfoJSONRPC struct {
	Number       *ethtypes.HexInteger        `json:"number"`
	Hash         ethtypes.HexBytes0xPrefix   `json:"hash"`
	ParentHash   ethtypes.HexBytes0xPrefix   `json:"parentHash"`
	Timestamp    *ethtypes.HexInteger        `json:"timestamp"`
	LogsBloom    ethtypes.HexBytes0xPrefix   `json:"logsBloom"`
	Transactions []ethtypes.HexBytes0xPrefix `json:"transactions"`
}

func (bi *BlockInfoJSONRPC) MarshalFormat(ctx context.Context, format JSONFormatOptions, opts ...MarshalOption) (_ []byte, err error) {
	txnArray := make([]any, len(bi.Transactions))
	for i, t := range bi.Transactions {
		txnArray[i] = ([]byte)(t)
	}
	return format.MarshalFormattedMap(ctx, map[string]any{
		"number":       (*big.Int)(bi.Number),
		"hash":         ([]byte)(bi.Hash),
		"parentHash":   ([]byte)(bi.ParentHash),
		"timestamp":    (*big.Int)(bi.Timestamp),
		"logsBloom":    ([]byte)(bi.LogsBloom),
		"transactions": txnArray,
	}, opts...)
}
