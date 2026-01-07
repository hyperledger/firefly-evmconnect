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

import "github.com/hyperledger/firefly-signer/pkg/ethtypes"

// TxReceiptJSONRPC is the receipt obtained over JSON/RPC from the ethereum client, with gas used, logs and contract address
type TxReceiptJSONRPC struct {
	BlockHash         ethtypes.HexBytes0xPrefix  `json:"blockHash"`
	BlockNumber       *ethtypes.HexInteger       `json:"blockNumber"`
	ContractAddress   *ethtypes.Address0xHex     `json:"contractAddress"`
	CumulativeGasUsed *ethtypes.HexInteger       `json:"cumulativeGasUsed"`
	From              *ethtypes.Address0xHex     `json:"from"`
	GasUsed           *ethtypes.HexInteger       `json:"gasUsed"`
	Logs              []*LogJSONRPC              `json:"logs"`
	Status            *ethtypes.HexInteger       `json:"status"`
	To                *ethtypes.Address0xHex     `json:"to"`
	TransactionHash   ethtypes.HexBytes0xPrefix  `json:"transactionHash"`
	TransactionIndex  *ethtypes.HexInteger       `json:"transactionIndex"`
	RevertReason      *ethtypes.HexBytes0xPrefix `json:"revertReason"`
}

// TxInfoJSONRPC is the transaction info obtained over JSON/RPC from the ethereum client, with input data
type TxInfoJSONRPC struct {
	BlockHash        ethtypes.HexBytes0xPrefix `json:"blockHash"`   // null if pending
	BlockNumber      *ethtypes.HexInteger      `json:"blockNumber"` // null if pending
	From             *ethtypes.Address0xHex    `json:"from"`
	Gas              *ethtypes.HexInteger      `json:"gas"`
	GasPrice         *ethtypes.HexInteger      `json:"gasPrice"`
	Hash             ethtypes.HexBytes0xPrefix `json:"hash"`
	Input            ethtypes.HexBytes0xPrefix `json:"input"`
	R                *ethtypes.HexInteger      `json:"r"`
	S                *ethtypes.HexInteger      `json:"s"`
	To               *ethtypes.Address0xHex    `json:"to"`
	TransactionIndex *ethtypes.HexInteger      `json:"transactionIndex"` // null if pending
	V                *ethtypes.HexInteger      `json:"v"`
	Value            *ethtypes.HexInteger      `json:"value"`
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

// BlockInfoJSONRPC are the info fields we parse from the JSON/RPC response, and cache
type BlockInfoJSONRPC struct {
	Number       *ethtypes.HexInteger        `json:"number"`
	Hash         ethtypes.HexBytes0xPrefix   `json:"hash"`
	ParentHash   ethtypes.HexBytes0xPrefix   `json:"parentHash"`
	Timestamp    *ethtypes.HexInteger        `json:"timestamp"`
	LogsBloom    ethtypes.HexBytes0xPrefix   `json:"logsBloom"`
	Transactions []ethtypes.HexBytes0xPrefix `json:"transactions"`
}
