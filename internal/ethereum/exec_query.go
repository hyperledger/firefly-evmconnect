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

package ethereum

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-evmconnect/pkg/etherrors"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
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

	// Parse the optional errors JSON spec, if available
	errors, err := buildErrorsABI(ctx, req.TransactionInput.Errors)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Build the base transaction object
	tx, err := c.buildTx(ctx, txTypeQuery, req.From, req.To, req.Nonce, req.Gas, req.Value, callData)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Do the call, with processing of revert reasons
	outputs, reason, err := c.callTransaction(ctx, tx, method, errors, req.BlockNumber)
	if err != nil {
		return nil, reason, err
	}

	return &ffcapi.QueryInvokeResponse{
		Outputs: outputs,
	}, "", nil

}

func (c *ethConnector) attemptProcessingRevertData(ctx context.Context, errors []*abi.Entry, rpcErr *rpcbackend.RPCError) (ffcapi.ErrorReason, error) {
	// some Ethereum implementations (eg. geth 1.10) returns the revert data inside
	// the "error" object rather than the "result" object in the response
	if rpcErr.Data != "" {

		log.L(ctx).Debugf("Received error data in revert: %s", rpcErr.Data)
		var revertData ethtypes.HexBytes0xPrefix
		e1 := json.Unmarshal(rpcErr.Data.Bytes(), &revertData)
		if e1 != nil {
			log.L(ctx).Errorf("Failed to parse revert reason from error data: %s. Error: %+v", e1, rpcErr)
		} else {
			revertReason := processRevertReason(ctx, revertData, errors)
			if revertReason != "" {
				return ffcapi.ErrorReasonTransactionReverted, i18n.NewError(ctx, msgs.MsgReverted, revertReason)
			}
		}
	}
	return "", nil
}

func (c *ethConnector) callTransaction(ctx context.Context, tx *ethsigner.Transaction, method *abi.Entry, errors []*abi.Entry, blockNumber *string) (*fftypes.JSONAny, ffcapi.ErrorReason, error) {

	// Do the raw call
	var outputData ethtypes.HexBytes0xPrefix
	blockNumberStr := "latest"
	if blockNumber != nil {
		blockNumberStr = *blockNumber
	}
	rpcErr := c.backend.CallRPC(ctx, &outputData, "eth_call", tx, blockNumberStr)
	if rpcErr != nil {
		if reason, revertErr := c.attemptProcessingRevertData(ctx, errors, rpcErr); revertErr != nil {
			return nil, reason, revertErr
		}

		reason := etherrors.MapError(etherrors.CallRPCMethods, rpcErr.Error())
		err := rpcErr.Error()
		if reason == ffcapi.ErrorReasonTransactionReverted {
			err = i18n.NewError(ctx, msgs.MsgReverted, rpcErr.Error())
		}
		return nil, reason, err
	}

	// If we get back nil, then send back nil
	if len(outputData) == 0 {
		return nil, "", nil
	}

	// some Ethereum implementations return revert reason data in the response's result object,
	// check the output to see if there are error data and return proper errors
	revertReason := processRevertReason(ctx, outputData, errors)
	if revertReason != "" {
		return nil, ffcapi.ErrorReasonTransactionReverted, i18n.NewError(ctx, msgs.MsgReverted, revertReason)
	}

	if method == nil {
		// We got data back, but are ignoring at as we don't have a method to parse against
		log.L(ctx).Warnf("Data returned from call with no method signature: %s", outputData.String())
		return fftypes.JSONAnyPtr(fftypes.NullString), "", nil
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

// processRevertReason returns under 3 different circumstances:
// 1. non-empty string - parsed by us: valid reason has been successfully parsed
// 2. non-empty string - assumed to already be parsed by node: error detail was present but failed to parse, string was raw data
// 3. empty string: outputData is NOT an error detail data
func processRevertReason(ctx context.Context, outputData ethtypes.HexBytes0xPrefix, errorAbis []*abi.Entry) string {
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
					return unwrapNestedRevertReasons(ctx, strError, 0, errorAbis)
				}
			}
			log.L(ctx).Warnf("Invalid revert data: %s", outputData)
		} else if len(errorAbis) > 0 {
			// check if the signature matches any of the declared custom error definitions
			for _, e := range errorAbis {
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
		// we call this "transient error" because it signals to the caller of the case
		// that the raw revert data is returned, then it gets thrown away. so no need to translate
		log.L(ctx).Debugf("Directly returning revert reason: %s", outputData)
		return outputData.String()
	}
	return ""
}

const maxNestedRevertDepth = 10

// unwrapNestedRevertReasons handles Solidity contracts that catch a revert's raw bytes
// and re-throw them inside a new Error(string) by doing string(reason). This produces
// an Error(string) whose decoded "string" contains raw ABI-encoded error data
// (including null bytes from ABI padding). We scan for all known error selectors
// (Error(string) plus any custom errors from the ABI), decode the earliest match,
// and recurse for nested Error(string) chains.
func unwrapNestedRevertReasons(ctx context.Context, s string, depth int, errorAbis []*abi.Entry) string {
	if depth >= maxNestedRevertDepth {
		return sanitizeBinaryString([]byte(s))
	}

	raw := []byte(s)

	// Find the earliest occurrence of any known error selector
	bestIdx := -1
	var bestEntry *abi.Entry
	if idx := bytes.Index(raw, defaultErrorID); idx >= 0 {
		bestIdx = idx
		bestEntry = defaultError
	}
	for _, e := range errorAbis {
		sel := e.FunctionSelectorBytes()
		if idx := bytes.Index(raw, sel); idx >= 0 && (bestIdx < 0 || idx < bestIdx) {
			bestIdx = idx
			bestEntry = e
		}
	}

	if bestIdx < 0 {
		return sanitizeBinaryString(raw)
	}

	prefix := sanitizeBinaryString(raw[:bestIdx])
	embedded := raw[bestIdx:]

	if bestEntry == defaultError {
		errorInfo, err := defaultError.DecodeCallDataCtx(ctx, embedded)
		if err == nil && len(errorInfo.Children) == 1 {
			if nested, ok := errorInfo.Children[0].Value.(string); ok {
				return prefix + unwrapNestedRevertReasons(ctx, nested, depth+1, errorAbis)
			}
		}
	} else {
		formatted := formatCustomError(ctx, bestEntry, embedded)
		if formatted != "" {
			return prefix + formatted
		}
	}

	log.L(ctx).Debugf("Could not decode nested revert at depth %d, hex-encoding remaining %d bytes", depth, len(embedded))
	return prefix + "0x" + hex.EncodeToString(embedded)
}

// sanitizeBinaryString returns the input as a text string if it is entirely
// printable ASCII, or hex-encodes the entire input otherwise. This all-or-nothing
// approach avoids guessing where "readable" ends in an ambiguous binary blob.
func sanitizeBinaryString(raw []byte) string {
	for _, b := range raw {
		if b < 32 || b >= 127 {
			return "0x" + hex.EncodeToString(raw)
		}
	}
	return string(raw)
}

func formatCustomError(ctx context.Context, e *abi.Entry, outputData ethtypes.HexBytes0xPrefix) string {
	errorInfo, err := e.DecodeCallDataCtx(ctx, outputData)
	if err == nil {
		strError := fmt.Sprintf("%s(", e.Name)
		for i, child := range errorInfo.Children {
			strError += formatErrorComponent(ctx, child)
			if i < len(errorInfo.Children)-1 {
				strError += ", "
			}
		}
		strError += ")"
		return strError
	}
	return ""
}

func formatErrorComponent(ctx context.Context, child *abi.ComponentValue) string {
	value, err := child.JSON()
	if err != nil {
		// if this part of the error structure failed to parse, simply append "?"
		log.L(ctx).Warnf("Failed to parse component value in error: %+v", child)
		return "?"
	}
	return string(value)
}
