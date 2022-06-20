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

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// TransactionReceipt is the receipt obtained over JSON/RPC from the ethereum client
type TransactionReceipt struct {
	BlockHash         *ethtypes.HexBytes0xPrefix `json:"blockHash"`
	BlockNumber       *ethtypes.HexInteger       `json:"blockNumber"`
	ContractAddress   *ethtypes.Address0xHex     `json:"contractAddress"`
	CumulativeGasUsed *ethtypes.HexInteger       `json:"cumulativeGasUsed"`
	TransactionHash   *ethtypes.HexBytes0xPrefix `json:"transactionHash"`
	From              *ethtypes.Address0xHex     `json:"from"`
	GasUsed           *ethtypes.HexInteger       `json:"gasUsed"`
	Status            *ethtypes.HexInteger       `json:"status"`
	To                *ethtypes.Address0xHex     `json:"to"`
	TransactionIndex  *ethtypes.HexInteger       `json:"transactionIndex"`
}

func (c *ethConnector) TransactionReceipt(ctx context.Context, req *ffcapi.TransactionReceiptRequest) (*ffcapi.TransactionReceiptResponse, ffcapi.ErrorReason, error) {

	// Get the receipt in the back-end JSON/RPC format
	var ethReceipt TransactionReceipt
	err := c.backend.Invoke(ctx, &ethReceipt, "eth_getTransactionReceipt", req.TransactionHash)
	if err != nil {
		return nil, "", err
	}
	isMined := ethReceipt.BlockHash != nil && ethReceipt.BlockNumber != nil && ethReceipt.BlockNumber.BigInt().Uint64() > 0
	if !isMined {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgReceiptNotAvailable, req.TransactionHash)
	}
	isSuccess := (ethReceipt.Status != nil && ethReceipt.Status.BigInt().Int64() > 0)

	fullReceipt, _ := json.Marshal(&ethReceipt)

	var txIndex int64
	if ethReceipt.TransactionIndex != nil {
		txIndex = ethReceipt.TransactionIndex.BigInt().Int64()
	}
	return &ffcapi.TransactionReceiptResponse{
		BlockNumber:      (*fftypes.FFBigInt)(ethReceipt.BlockNumber),
		TransactionIndex: fftypes.NewFFBigInt(txIndex),
		BlockHash:        ethReceipt.BlockHash.String(),
		Success:          isSuccess,
		ExtraInfo:        fftypes.JSONAnyPtrBytes(fullReceipt),
	}, "", nil

}
