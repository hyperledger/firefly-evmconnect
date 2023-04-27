// Copyright © 2023 Kaleido, Inc.
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// txReceiptJSONRPC is the receipt obtained over JSON/RPC from the ethereum client, with gas used, logs and contract address
type txReceiptJSONRPC struct {
	BlockHash         ethtypes.HexBytes0xPrefix `json:"blockHash"`
	BlockNumber       *ethtypes.HexInteger      `json:"blockNumber"`
	ContractAddress   *ethtypes.Address0xHex    `json:"contractAddress"`
	CumulativeGasUsed *ethtypes.HexInteger      `json:"cumulativeGasUsed"`
	From              *ethtypes.Address0xHex    `json:"from"`
	GasUsed           *ethtypes.HexInteger      `json:"gasUsed"`
	Logs              []*logJSONRPC             `json:"logs"`
	Status            *ethtypes.HexInteger      `json:"status"`
	To                *ethtypes.Address0xHex    `json:"to"`
	TransactionHash   ethtypes.HexBytes0xPrefix `json:"transactionHash"`
	TransactionIndex  *ethtypes.HexInteger      `json:"transactionIndex"`
}

// receiptExtraInfo is the version of the receipt we store under the TX.
// - We omit the full logs from the JSON/RPC
// - We omit fields already in the standardized cross-blockchain section
// - We format numbers as decimals
type receiptExtraInfo struct {
	ContractAddress   *ethtypes.Address0xHex `json:"contractAddress"`
	CumulativeGasUsed *fftypes.FFBigInt      `json:"cumulativeGasUsed"`
	From              *ethtypes.Address0xHex `json:"from"`
	To                *ethtypes.Address0xHex `json:"to"`
	GasUsed           *fftypes.FFBigInt      `json:"gasUsed"`
	Status            *fftypes.FFBigInt      `json:"status"`
	ReturnValue       *string                `json:"returnValue"`
}

// txInfoJSONRPC is the transaction info obtained over JSON/RPC from the ethereum client, with input data
type txInfoJSONRPC struct {
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

type StructLog struct {
	PC      *fftypes.FFBigInt `json:"pc"`
	Op      *string           `json:"op"`
	Gas     *fftypes.FFBigInt `json:"gas"`
	GasCost *fftypes.FFBigInt `json:"gasCost"`
	Depth   *fftypes.FFBigInt `json:"depth"`
	Stack   []*string         `json:"stack"`
	Memory  []*string         `json:"memory"`
	Reason  *string           `json:"reason"`
}
type txDebugTrace struct {
	Gas         *fftypes.FFBigInt `json:"gas"`
	Failed      bool              `json:"failed"`
	ReturnValue string            `json:"returnValue"`
	StructLogs  []StructLog       `json:"structLogs"`
}

func (c *ethConnector) getTransactionInfo(ctx context.Context, hash ethtypes.HexBytes0xPrefix) (*txInfoJSONRPC, error) {
	var txInfo *txInfoJSONRPC
	cached, ok := c.txCache.Get(hash.String())
	if ok {
		return cached.(*txInfoJSONRPC), nil
	}

	rpcErr := c.backend.CallRPC(ctx, &txInfo, "eth_getTransactionByHash", hash)
	var err error
	if rpcErr != nil {
		err = rpcErr.Error()
	} else {
		c.txCache.Add(hash.String(), txInfo)
	}
	return txInfo, err
}

func ProtocolIDForReceipt(blockNumber, transactionIndex *fftypes.FFBigInt) string {
	if blockNumber != nil && transactionIndex != nil {
		return fmt.Sprintf("%.12d/%.6d", blockNumber.Int(), transactionIndex.Int())
	}
	return ""
}

func (c *ethConnector) TransactionReceipt(ctx context.Context, req *ffcapi.TransactionReceiptRequest) (*ffcapi.TransactionReceiptResponse, ffcapi.ErrorReason, error) {

	// Get the receipt in the back-end JSON/RPC format
	var ethReceipt *txReceiptJSONRPC
	rpcErr := c.backend.CallRPC(ctx, &ethReceipt, "eth_getTransactionReceipt", req.TransactionHash)
	if rpcErr != nil {
		return nil, "", rpcErr.Error()
	}
	if ethReceipt == nil {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgReceiptNotAvailable, req.TransactionHash)
	}
	isSuccess := (ethReceipt.Status != nil && ethReceipt.Status.BigInt().Int64() > 0)

	var transactionReturnValue *string

	if !isSuccess {
		var debugTrace *txDebugTrace

		traceErr := c.backend.CallRPC(ctx, &debugTrace, "debug_traceTransaction", req.TransactionHash)
		if traceErr != nil {
			log.L(ctx).Debugf("Ignoring error from debug_traceTransaction: %s ", traceErr.Message)
			transactionReturnValue = nil
		} else {
			returnValue := debugTrace.ReturnValue
			if returnValue == "" {
				// some clients (e.g. Besu) include the error reason on the final struct log
				if len(debugTrace.StructLogs) > 0 {
					finalStructLog := debugTrace.StructLogs[len(debugTrace.StructLogs)-1]
					if *finalStructLog.Op == "REVERT" && finalStructLog.Reason != nil {
						returnValue = *finalStructLog.Reason
					}
				}
			}
			if returnValue != "" {
				returnValue = strings.TrimPrefix(returnValue, "0x")
				returnValueASCII, decodeErr := hex.DecodeString(returnValue)
				if decodeErr != nil {
					log.L(ctx).Debugf("Ignoring error decoding result from debug_traceTransaction: %s ", decodeErr)

				}
				printableString := strings.Map(func(r rune) rune {
					if unicode.IsPrint(r) {
						return r
					}
					return -1
				}, string(returnValueASCII))
				transactionReturnValue = &printableString
			}
		}
	}

	ethReceipt.Logs = nil
	fullReceipt, _ := json.Marshal(&receiptExtraInfo{
		ContractAddress:   ethReceipt.ContractAddress,
		CumulativeGasUsed: (*fftypes.FFBigInt)(ethReceipt.CumulativeGasUsed),
		From:              ethReceipt.From,
		To:                ethReceipt.To,
		GasUsed:           (*fftypes.FFBigInt)(ethReceipt.GasUsed),
		Status:            (*fftypes.FFBigInt)(ethReceipt.Status),
		ReturnValue:       transactionReturnValue,
	})

	var txIndex int64
	if ethReceipt.TransactionIndex != nil {
		txIndex = ethReceipt.TransactionIndex.BigInt().Int64()
	}
	receiptResponse := &ffcapi.TransactionReceiptResponse{
		BlockNumber:      (*fftypes.FFBigInt)(ethReceipt.BlockNumber),
		TransactionIndex: fftypes.NewFFBigInt(txIndex),
		BlockHash:        ethReceipt.BlockHash.String(),
		Success:          isSuccess,
		ProtocolID:       ProtocolIDForReceipt((*fftypes.FFBigInt)(ethReceipt.BlockNumber), fftypes.NewFFBigInt(txIndex)),
		ExtraInfo:        fftypes.JSONAnyPtrBytes(fullReceipt),
	}
	if ethReceipt.ContractAddress != nil {
		location, _ := json.Marshal(map[string]string{
			"address": ethReceipt.ContractAddress.String(),
		})
		receiptResponse.ContractLocation = fftypes.JSONAnyPtrBytes(location)
	}
	return receiptResponse, "", nil

}
