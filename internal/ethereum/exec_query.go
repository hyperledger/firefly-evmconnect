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

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
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
	defaultErrorID = defaultError.FunctionSelectorBytes()
)

func (c *ethConnector) QueryInvoke(ctx context.Context, req *ffcapi.QueryInvokeRequest) (*ffcapi.QueryInvokeResponse, ffcapi.ErrorReason, error) {
	// Parse the input JSON data, to build the call data
	callData, method, err := c.prepareCallData(ctx, &req.TransactionInput)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	errors := make([]*abi.Entry, len(req.Errors))
	for i, e := range req.Errors {
		err := json.Unmarshal(e.Bytes(), &errors[i])
		if err != nil {
			return nil, ffcapi.ErrorReasonInvalidInputs, i18n.NewError(ctx, msgs.MsgUnmarshalABIFail, err)
		}
	}

	// Build the base transaction object
	tx, err := c.buildTx(ctx, txTypeQuery, req.From, req.To, req.Nonce, req.Gas, req.Value, callData)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Do the call, with processing of revert reasons
	outputs, reason, err := c.callTransaction(ctx, tx, method, errors)
	if err != nil {
		return nil, reason, err
	}

	return &ffcapi.QueryInvokeResponse{
		Outputs: outputs,
	}, "", nil

}

func (c *ethConnector) callTransaction(ctx context.Context, tx *ethsigner.Transaction, method *abi.Entry, errors ...[]*abi.Entry) (*fftypes.JSONAny, ffcapi.ErrorReason, error) {

	// Do the raw call
	var outputData ethtypes.HexBytes0xPrefix
	rpcRes, err := c.backend.CallRPC(ctx, &outputData, "eth_call", tx, "latest")
	if err != nil {
		return nil, mapError(callRPCMethods, err), err
	}

	// If we get back nil, then send back nil
	if len(outputData) == 0 {
		return nil, "", nil
	}

	// some Ethereum implementations return 200 with error data,
	// check the output to see if there are error data and return proper errors
	revertReason := processRevertReason(ctx, outputData, errors...)
	if revertReason != "" {
		return nil, ffcapi.ErrorReasonTransactionReverted, i18n.NewError(ctx, msgs.MsgRevertedWithMessage, revertReason)
	}

	// Parse the data against the outputs
	var jsonData []byte
	outputValueTree, err := method.Outputs.DecodeABIDataCtx(ctx, outputData, 0)
	if err == nil {
		// Serialize down to JSON, and wrap in a JSONAny
		jsonData, err = c.serializer.SerializeJSONCtx(ctx, outputValueTree)
	}
	if err != nil {
		log.L(ctx).Warnf("Invalid return data: %s", outputData)
		return nil, "", i18n.NewError(ctx, msgs.MsgReturnDataInvalid, err)
	}
	return fftypes.JSONAnyPtrBytes(jsonData), "", nil

}

func processRevertReason(ctx context.Context, outputData ethtypes.HexBytes0xPrefix, errors ...[]*abi.Entry) string {
	// Check for a revert - we can determine it is calldata (with an error signature)
	// that is returned by the fact the output is not a multiple of 32 (as all ABI encodings
	// result in a multiple of 32 bytes) and has exactly 4 extra bytes for a function
	// signature
	if len(outputData)%32 == 4 {
		signature := outputData[0:4]
		if bytes.Equal(signature, defaultErrorID) {
			errorInfo, err := defaultError.DecodeCallDataCtx(ctx, outputData)
			if err == nil && len(errorInfo.Children) == 1 {
				if strError, ok := errorInfo.Children[0].Value.(string); ok {
					return strError
				}
			}
			log.L(ctx).Warnf("Invalid revert data: %s", outputData)
		} else {
			// check if the signature matches any of the declared custom error definitions
			if len(errors) > 0 {
				for _, e := range errors[0] {
					idBytes := e.FunctionSelectorBytes()
					if bytes.Equal(signature, idBytes) {
						err := formatCustomError(ctx, e, outputData)
						if err == "" {
							log.L(ctx).Warnf("Invalid revert data: %s", outputData)
							break
						}
						return err
					}
				}
			}
		}
		return outputData.String()
	}
	return ""
}

func formatCustomError(ctx context.Context, e *abi.Entry, outputData ethtypes.HexBytes0xPrefix) string {
	errorInfo, err := e.DecodeCallDataCtx(ctx, outputData)
	if err == nil {
		strError := fmt.Sprintf("%s(", e.Name)
		for i, child := range errorInfo.Children {
			value, err := child.JSON()
			if err == nil {
				strError += string(value)
			} else {
				// if this part of the error structure failed to parse, simply append "?"
				strError += "?"
			}
			if i < len(errorInfo.Children)-1 {
				strError += ", "
			}
		}
		strError += ")"
		return strError
	}
	return ""
}
