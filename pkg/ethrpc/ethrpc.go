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
	"encoding/json"
	"math/big"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// TxReceiptJSONRPC is the receipt obtained over JSON/RPC from the ethereum client, with gas used, logs and contract address
type TxReceiptJSONRPC struct {
	TransactionHash   ethtypes.HexBytes0xPrefix `json:"transactionHash"`
	TransactionIndex  *ethtypes.HexInteger      `json:"transactionIndex"`
	BlockHash         ethtypes.HexBytes0xPrefix `json:"blockHash"`
	BlockNumber       ethtypes.HexUint64        `json:"blockNumber"`
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

func (txr *TxReceiptJSONRPC) MarshalFormat(jss *JSONSerializerSet, opts ...MarshalOption) (jb json.RawMessage, err error) {
	logsArray := make([]json.RawMessage, len(txr.Logs))
	for i, l := range txr.Logs {
		if err == nil {
			logsArray[i], err = l.MarshalFormat(jss, opts...)
		}
	}
	if err == nil {
		jb, err = jss.MarshalFormattedMap(map[string]any{
			"transactionHash":   ([]byte)(txr.TransactionHash),
			"transactionIndex":  (*big.Int)(txr.TransactionIndex),
			"blockHash":         ([]byte)(txr.BlockHash),
			"blockNumber":       (*uint64)(&txr.BlockNumber),
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

func (txi *TxInfoJSONRPC) MarshalFormat(jss *JSONSerializerSet, opts ...MarshalOption) (_ json.RawMessage, err error) {
	return jss.MarshalFormattedMap(map[string]any{
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

// See https://ethereum.org/hr/developers/docs/apis/json-rpc/#eth_newfilter
// The address, as well as the entries in the topic array, can be DATA|Array.
// We just use array in all cases.
type LogFilterJSONRPC struct {
	FromBlock *ethtypes.HexInteger          `json:"fromBlock,omitempty"`
	ToBlock   *ethtypes.HexInteger          `json:"toBlock,omitempty"`
	Address   []*ethtypes.Address0xHex      `json:"address,omitempty"`
	Topics    [][]ethtypes.HexBytes0xPrefix `json:"topics,omitempty"`
}

type LogJSONRPC struct {
	Removed          bool                        `json:"removed"`
	LogIndex         *ethtypes.HexInteger        `json:"logIndex"`
	TransactionIndex *ethtypes.HexInteger        `json:"transactionIndex"`
	BlockNumber      ethtypes.HexUint64          `json:"blockNumber"`
	TransactionHash  ethtypes.HexBytes0xPrefix   `json:"transactionHash"`
	BlockHash        ethtypes.HexBytes0xPrefix   `json:"blockHash"`
	Address          *ethtypes.Address0xHex      `json:"address"`
	Data             ethtypes.HexBytes0xPrefix   `json:"data"`
	Topics           []ethtypes.HexBytes0xPrefix `json:"topics"`
}

func (l *LogJSONRPC) MarshalFormat(jss *JSONSerializerSet, opts ...MarshalOption) (_ json.RawMessage, err error) {
	topicsArray := make([]any, len(l.Topics))
	for i, t := range l.Topics {
		topicsArray[i] = ([]byte)(t)
	}
	return jss.MarshalFormattedMap(map[string]any{
		"removed":          l.Removed,
		"logIndex":         (*big.Int)(l.LogIndex),
		"transactionIndex": (*big.Int)(l.TransactionIndex),
		"blockNumber":      (*uint64)(&l.BlockNumber),
		"transactionHash":  ([]byte)(l.TransactionHash),
		"blockHash":        ([]byte)(l.BlockHash),
		"address":          (*[20]byte)(l.Address),
		"data":             ([]byte)(l.Data),
		"topics":           topicsArray,
	}, opts...)
}

// BlockInfoJSONRPC are the info fields we parse from the JSON/RPC response, and cache
type BlockInfoJSONRPC struct {
	Number       ethtypes.HexUint64          `json:"number"`
	Hash         ethtypes.HexBytes0xPrefix   `json:"hash"`
	ParentHash   ethtypes.HexBytes0xPrefix   `json:"parentHash"`
	Timestamp    *ethtypes.HexInteger        `json:"timestamp"`
	LogsBloom    ethtypes.HexBytes0xPrefix   `json:"logsBloom"`
	Transactions []ethtypes.HexBytes0xPrefix `json:"transactions"`
}

func (bi *BlockInfoJSONRPC) MarshalFormat(jss *JSONSerializerSet, opts ...MarshalOption) (_ json.RawMessage, err error) {
	txnArray := make([]any, len(bi.Transactions))
	for i, t := range bi.Transactions {
		txnArray[i] = ([]byte)(t)
	}
	return jss.MarshalFormattedMap(map[string]any{
		"number":       (*uint64)(&bi.Number),
		"hash":         ([]byte)(bi.Hash),
		"parentHash":   ([]byte)(bi.ParentHash),
		"timestamp":    (*big.Int)(bi.Timestamp),
		"logsBloom":    ([]byte)(bi.LogsBloom),
		"transactions": txnArray,
	}, opts...)
}

func (bi *BlockInfoJSONRPC) Equal(bi2 *BlockInfoJSONRPC) bool {
	return bi.Hash.Equals(bi2.Hash) &&
		bi.ParentHash.Equals(bi2.ParentHash) &&
		bi.Number == bi2.Number
}

func (bi *BlockInfoJSONRPC) IsParentOf(other *BlockInfoJSONRPC) bool {
	return bi.Hash.Equals(other.ParentHash) && (bi.Number.Uint64()+1) == other.Number.Uint64()
}

func (bi *BlockInfoJSONRPC) ToFFCAPIMinimalBlockInfo() *ffcapi.MinimalBlockInfo {
	return &ffcapi.MinimalBlockInfo{
		BlockNumber: fftypes.FFuint64(bi.Number.Uint64()),
		BlockHash:   bi.Hash.String(),
		ParentHash:  bi.ParentHash.String(),
	}
}

type BlockHeaderJSONRPC struct {
	Number           ethtypes.HexUint64          `json:"number"`
	Hash             ethtypes.HexBytes0xPrefix   `json:"hash"`
	MixHash          ethtypes.HexBytes0xPrefix   `json:"mixHash"`
	ParentHash       ethtypes.HexBytes0xPrefix   `json:"parentHash"`
	Nonce            ethtypes.HexBytes0xPrefix   `json:"nonce"`
	SHA3Uncles       ethtypes.HexBytes0xPrefix   `json:"sha3Uncles"`
	LogsBloom        ethtypes.HexBytes0xPrefix   `json:"logsBloom"`
	TransactionsRoot ethtypes.HexBytes0xPrefix   `json:"transactionsRoot"`
	StateRoot        ethtypes.HexBytes0xPrefix   `json:"stateRoot"`
	ReceiptsRoot     ethtypes.HexBytes0xPrefix   `json:"receiptsRoot"`
	Miner            *ethtypes.Address0xHex      `json:"miner"`
	Difficulty       *ethtypes.HexInteger        `json:"difficulty"`
	TotalDifficulty  *ethtypes.HexInteger        `json:"totalDifficulty"`
	ExtraData        ethtypes.HexBytes0xPrefix   `json:"extraData"`
	BaseFeePerGas    *ethtypes.HexInteger        `json:"baseFeePerGas"`
	Size             *ethtypes.HexInteger        `json:"size"`
	GasLimit         *ethtypes.HexInteger        `json:"gasLimit"`
	GasUsed          *ethtypes.HexInteger        `json:"gasUsed"`
	Timestamp        *ethtypes.HexInteger        `json:"timestamp"`
	Uncles           []ethtypes.HexBytes0xPrefix `json:"uncles"`
}

func (b *BlockHeaderJSONRPC) getFormatMap() map[string]any {
	unclesArray := make([]any, len(b.Uncles))
	for i, uncle := range b.Uncles {
		unclesArray[i] = ([]byte)(uncle)
	}
	return map[string]any{
		"number":           (*uint64)(&b.Number),
		"hash":             ([]byte)(b.Hash),
		"mixHash":          ([]byte)(b.MixHash),
		"parentHash":       ([]byte)(b.ParentHash),
		"nonce":            ([]byte)(b.Nonce),
		"sha3Uncles":       ([]byte)(b.SHA3Uncles),
		"logsBloom":        ([]byte)(b.LogsBloom),
		"transactionsRoot": ([]byte)(b.TransactionsRoot),
		"stateRoot":        ([]byte)(b.StateRoot),
		"receiptsRoot":     ([]byte)(b.ReceiptsRoot),
		"miner":            (*[20]byte)(b.Miner),
		"difficulty":       (*big.Int)(b.Difficulty),
		"totalDifficulty":  (*big.Int)(b.TotalDifficulty),
		"extraData":        ([]byte)(b.ExtraData),
		"baseFeePerGas":    (*big.Int)(b.BaseFeePerGas),
		"size":             (*big.Int)(b.Size),
		"gasLimit":         (*big.Int)(b.GasLimit),
		"gasUsed":          (*big.Int)(b.GasUsed),
		"timestamp":        (*big.Int)(b.Timestamp),
		"uncles":           unclesArray,
	}
}

func (b *BlockHeaderJSONRPC) ToBlockInfo(includeLogsBloom bool) *BlockInfoJSONRPC {
	bi := &BlockInfoJSONRPC{
		Number:     b.Number,
		Hash:       b.Hash,
		ParentHash: b.ParentHash,
		Timestamp:  b.Timestamp,
	}
	if includeLogsBloom {
		bi.LogsBloom = b.LogsBloom
	}
	return bi
}

// FullBlockWithTxHashesJSONRPC is the full JSON/RPC structure you get with "false" on eth_getBlockByNumber / eth_getBlockByHash
type FullBlockWithTxHashesJSONRPC struct {
	BlockHeaderJSONRPC
	Transactions []ethtypes.HexBytes0xPrefix `json:"transactions"`
}

func (b *FullBlockWithTxHashesJSONRPC) ToBlockInfo(includeLogsBloom bool) *BlockInfoJSONRPC {
	if b == nil {
		return nil
	}
	bi := b.BlockHeaderJSONRPC.ToBlockInfo(includeLogsBloom)
	bi.Transactions = b.Transactions
	return bi
}

// FullBlockWithTransactionsJSONRPC is the full JSON/RPC structure you get with "true" on eth_getBlockByNumber / eth_getBlockByHash
type FullBlockWithTransactionsJSONRPC struct {
	BlockHeaderJSONRPC
	Transactions []*TxInfoJSONRPC `json:"transactions"`
}

func (b *FullBlockWithTransactionsJSONRPC) ToBlockInfo(includeLogsBloom bool) *BlockInfoJSONRPC {
	if b == nil {
		return nil
	}
	bi := b.BlockHeaderJSONRPC.ToBlockInfo(includeLogsBloom)
	bi.Transactions = make([]ethtypes.HexBytes0xPrefix, len(b.Transactions))
	for i, t := range b.Transactions {
		bi.Transactions[i] = t.Hash
	}
	return bi
}

func (b *FullBlockWithTxHashesJSONRPC) MarshalFormat(jss *JSONSerializerSet, opts ...MarshalOption) (_ json.RawMessage, err error) {
	txnHashArray := make([]any, len(b.Transactions))
	for i, t := range b.Transactions {
		txnHashArray[i] = ([]byte)(t)
	}
	formatMap := b.BlockHeaderJSONRPC.getFormatMap()
	formatMap["transactions"] = txnHashArray
	return jss.MarshalFormattedMap(formatMap, opts...)
}

func (b *FullBlockWithTransactionsJSONRPC) MarshalFormat(jss *JSONSerializerSet, opts ...MarshalOption) (jb json.RawMessage, err error) {
	txnsArray := make([]json.RawMessage, len(b.Transactions))
	for i, l := range b.Transactions {
		if err == nil {
			txnsArray[i], err = l.MarshalFormat(jss, opts...)
		}
	}
	if err == nil {
		formatMap := b.BlockHeaderJSONRPC.getFormatMap()
		formatMap["transactions"] = txnsArray
		jb, err = jss.MarshalFormattedMap(formatMap, opts...)
	}
	return jb, err
}
