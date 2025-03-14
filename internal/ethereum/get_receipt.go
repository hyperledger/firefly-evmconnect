// Copyright © 2025 Kaleido, Inc.
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

// txReceiptJSONRPC is the receipt obtained over JSON/RPC from the ethereum client, with gas used, logs and contract address
type txReceiptJSONRPC struct {
	BlockHash         ethtypes.HexBytes0xPrefix  `json:"blockHash"`
	BlockNumber       *ethtypes.HexInteger       `json:"blockNumber"`
	ContractAddress   *ethtypes.Address0xHex     `json:"contractAddress"`
	CumulativeGasUsed *ethtypes.HexInteger       `json:"cumulativeGasUsed"`
	From              *ethtypes.Address0xHex     `json:"from"`
	GasUsed           *ethtypes.HexInteger       `json:"gasUsed"`
	Logs              []*logJSONRPC              `json:"logs"`
	Status            *ethtypes.HexInteger       `json:"status"`
	To                *ethtypes.Address0xHex     `json:"to"`
	TransactionHash   ethtypes.HexBytes0xPrefix  `json:"transactionHash"`
	TransactionIndex  *ethtypes.HexInteger       `json:"transactionIndex"`
	RevertReason      *ethtypes.HexBytes0xPrefix `json:"revertReason"`
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
	ErrorMessage      *string                `json:"errorMessage"`
	ReturnValue       *string                `json:"returnValue,omitempty"`
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

func padHexData(hexString string) string {
	hexString = strings.TrimPrefix(hexString, "0x")
	if len(hexString)%2 == 1 {
		hexString = "0" + hexString
	}

	return hexString
}

func (c *ethConnector) getErrorInfo(ctx context.Context, transactionHash string, revertFromReceipt *ethtypes.HexBytes0xPrefix) (pReturnValue *string, pErrorMessage *string) {

	var revertReason string
	if revertFromReceipt == nil {
		// Tracing a transaction to get revert information is expensive so it's not enabled by default
		if c.traceTXForRevertReason {
			log.L(ctx).Trace("No revert reason for the failed transaction found in the receipt. Calling debug_traceTransaction to retrieve it.")
			// Attempt to get the return value of the transaction - not possible on all RPC endpoints
			var debugTrace *txDebugTrace
			traceErr := c.backend.CallRPC(ctx, &debugTrace, "debug_traceTransaction", transactionHash)
			if traceErr != nil {
				msg := i18n.NewError(ctx, msgs.MsgUnableToCallDebug, traceErr).Error()
				return nil, &msg
			}

			revertReason = debugTrace.ReturnValue
			log.L(ctx).Debugf("Revert reason from debug_traceTransaction: '%v'", revertReason)
			if revertReason == "" {
				// some clients (e.g. Besu) include the error reason on the final struct log
				if len(debugTrace.StructLogs) > 0 {
					finalStructLog := debugTrace.StructLogs[len(debugTrace.StructLogs)-1]
					if *finalStructLog.Op == "REVERT" && finalStructLog.Reason != nil {
						revertReason = *finalStructLog.Reason
					}
				}
			}
		}
	} else {
		log.L(ctx).Trace("Revert reason is set in the receipt. Skipping call to debug_traceTransaction.")
		revertReason = revertFromReceipt.String()
	}

	// See if the return value is using the default error you get from "revert"
	var errorMessage string
	returnDataBytes, _ := hex.DecodeString(padHexData(revertReason))
	if len(returnDataBytes) > 4 && bytes.Equal(returnDataBytes[0:4], defaultErrorID) {
		value, err := defaultError.DecodeCallDataCtx(ctx, returnDataBytes)
		if err == nil {
			errorMessage = value.Children[0].Value.(string)
		}
	}

	// Otherwise we can't decode it, so put it directly in the error
	if errorMessage == "" {
		if len(returnDataBytes) > 0 {
			errorMessage = i18n.NewError(ctx, msgs.MsgReturnValueNotDecoded, revertReason).Error()
		} else {
			errorMessage = i18n.NewError(ctx, msgs.MsgReturnValueNotAvailable).Error()
		}
	}
	return &revertReason, &errorMessage
}

func (c *ethConnector) TransactionReceipt(ctx context.Context, req *ffcapi.TransactionReceiptRequest) (_ *ffcapi.TransactionReceiptResponse, _ ffcapi.ErrorReason, err error) {

	var filters []*eventFilter
	var methods []*abi.Entry
	if len(req.EventFilters) > 0 {
		// We need to post-process the logs and build a list of events
		_, filters, err = parseEventFilters(ctx, req.EventFilters)
		if err != nil {
			return nil, ffcapi.ErrorReasonInvalidInputs, err
		}
	}
	if len(req.Methods) > 0 {
		methods = make([]*abi.Entry, len(req.Methods))
		for i, m := range req.Methods {
			if err := json.Unmarshal(m.Bytes(), &methods[i]); err != nil {
				err = i18n.NewError(ctx, msgs.MsgUnmarshalABIMethodFail, err)
				return nil, ffcapi.ErrorReasonInvalidInputs, err
			}
		}
	}

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

	var returnDataString *string
	var transactionErrorMessage *string

	if !isSuccess {
		returnDataString, transactionErrorMessage = c.getErrorInfo(ctx, req.TransactionHash, ethReceipt.RevertReason)
	}

	fullReceipt, _ := json.Marshal(&receiptExtraInfo{
		ContractAddress:   ethReceipt.ContractAddress,
		CumulativeGasUsed: (*fftypes.FFBigInt)(ethReceipt.CumulativeGasUsed),
		From:              ethReceipt.From,
		To:                ethReceipt.To,
		GasUsed:           (*fftypes.FFBigInt)(ethReceipt.GasUsed),
		Status:            (*fftypes.FFBigInt)(ethReceipt.Status),
		ReturnValue:       returnDataString,
		ErrorMessage:      transactionErrorMessage,
	})

	var txIndex int64
	if ethReceipt.TransactionIndex != nil {
		txIndex = ethReceipt.TransactionIndex.BigInt().Int64()
	}
	receiptResponse := &ffcapi.TransactionReceiptResponse{
		TransactionReceiptResponseBase: ffcapi.TransactionReceiptResponseBase{

			BlockNumber:      (*fftypes.FFBigInt)(ethReceipt.BlockNumber),
			TransactionIndex: fftypes.NewFFBigInt(txIndex),
			BlockHash:        ethReceipt.BlockHash.String(),
			Success:          isSuccess,
			ProtocolID:       ProtocolIDForReceipt((*fftypes.FFBigInt)(ethReceipt.BlockNumber), fftypes.NewFFBigInt(txIndex)),
			ExtraInfo:        fftypes.JSONAnyPtrBytes(fullReceipt),
		},
	}
	if req.IncludeLogs {
		receiptResponse.Logs = make([]fftypes.JSONAny, len(ethReceipt.Logs))
		for i, l := range ethReceipt.Logs {
			b, _ := json.Marshal(l) // no error injectable here as we unmarshalled to a struct we control
			receiptResponse.Logs[i] = *fftypes.JSONAnyPtrBytes(b)
		}
	}
	// Try to decode the events etc. if we have filters supplied
	if len(filters) > 0 {
		ee := &eventEnricher{
			connector:     c,
			extractSigner: req.ExtractSigner,
		}
		for _, ethLog := range ethReceipt.Logs {
			var bestMatch *ffcapi.Event
			for _, f := range filters {
				event, matches, decoded, err := ee.filterEnrichEthLog(ctx, f, methods, ethLog)
				// If we matched and decoded, this is our best match (overriding any earlier)
				// If we only matched, then don't override a match+decode.
				// Example: ERC-20 & ERC-721 ABIs - both match, but only one decodes
				if (matches && err == nil) && (decoded || bestMatch == nil) {
					bestMatch = event
				}
			}
			if bestMatch != nil {
				receiptResponse.Events = append(receiptResponse.Events, bestMatch)
			}
		}

	}
	if ethReceipt.ContractAddress != nil {
		location, _ := json.Marshal(map[string]string{
			"address": ethReceipt.ContractAddress.String(),
		})
		receiptResponse.ContractLocation = fftypes.JSONAnyPtrBytes(location)
	}
	return receiptResponse, "", nil

}
