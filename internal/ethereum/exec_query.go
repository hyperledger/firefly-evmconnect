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

	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

var (
	// See https://docs.soliditylang.org/en/v0.8.14/control-structures.html#revert
	// There default error for `revert("some error")` is a function Error(string)
	defaultError = &abi.Entry{
		Type: abi.Error,
		Name: "Error",
		Inputs: abi.ParameterArray{
			{
				Type: "string",
			},
		},
	}
	defaultErrorID = defaultError.IDBytes()
)

func (c *ethConnector) execQuery(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.ExecQueryRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Parse the input JSON data, to build the call data
	callData, method, err := c.prepareCallData(ctx, &req.TransactionInput)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Build the base transaction object
	tx, err := c.buildTx(ctx, req.From, req.To, req.Nonce, req.Gas, req.Value, callData)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Do the call, with processing of revert reasons
	outputs, reason, err := c.callTransaction(ctx, tx, method)
	if err != nil {
		return nil, reason, err
	}

	return &ffcapi.ExecQueryResponse{
		Outputs: outputs,
	}, "", nil

}

func (c *ethConnector) callTransaction(ctx context.Context, tx *ethsigner.Transaction, method *abi.Entry) (*fftypes.JSONAny, ffcapi.ErrorReason, error) {

	// Do the raw call
	var outputData ethtypes.HexBytes0xPrefix
	err := c.backend.Invoke(ctx, &outputData, "eth_call", tx, "latest")
	if err != nil {
		return nil, mapError(callRPCMethods, err), err
	}

	// If we get back nil, then send back nil
	if len(outputData) == 0 {
		return nil, "", nil
	}

	// Check for a revert - we can determine it is calldata (with an error signature)
	// that is returned by the fact the output is not a multiple of 32 (as all ABI encodings
	// result in a multiple of 32 bytes) and has exactly 4 extra bytes for a function
	// signature
	if len(outputData)%32 == 4 {
		if bytes.Equal(outputData[0:4], defaultErrorID) {
			errorInfo, err := defaultError.DecodeCallDataCtx(ctx, outputData)
			if err == nil && len(errorInfo.Children) == 1 {
				if strError, ok := errorInfo.Children[0].Value.(string); ok {
					return nil, ffcapi.ErrorReasonTransactionReverted, i18n.NewError(ctx, msgs.MsgRevertedWithMessage, strError)
				}
			}
			log.L(ctx).Warnf("Invalid revert data: %s", outputData)
		}
		// Note: We do not support custom errors (with custom IDs/signatures).
		//       This would require the FFCAPI to be enhanced to allow an array
		//       "error" ABI definition entries to be passed alongside the
		//       "method" ABI definition entry.
		return nil, ffcapi.ErrorReasonTransactionReverted, i18n.NewError(ctx, msgs.MsgRevertedRawRevertData, outputData)
	}

	// Parse the data against the outputs
	outputValueTree, err := method.Outputs.DecodeABIDataCtx(ctx, outputData, 0)
	if err != nil {
		log.L(ctx).Warnf("Invalid return data: %s", outputData)
		return nil, "", i18n.NewError(ctx, msgs.MsgReturnDataInvalid, err)
	}

	// Serialize down to JSON, and wrap in a JSONAny
	jsonData, err := c.serializer.SerializeJSONCtx(ctx, outputValueTree)
	if err != nil {
		return nil, "", i18n.NewError(ctx, msgs.MsgReturnDataInvalid, err)
	}
	return fftypes.JSONAnyPtrBytes(jsonData), "", nil

}
