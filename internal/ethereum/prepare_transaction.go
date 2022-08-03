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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-evmconnect/internal/msgs"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi"
)

func (c *ethConnector) TransactionPrepare(ctx context.Context, req *ffcapi.TransactionPrepareRequest) (*ffcapi.TransactionPrepareResponse, ffcapi.ErrorReason, error) {

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

	if req.Gas == nil || req.Gas.Int().Sign() == 0 {
		// If a value for gas has not been supplied, do a gas estimate
		gas, reason, err := c.estimateGas(ctx, tx, method)
		if err != nil {
			return nil, reason, err
		}
		req.Gas = (*fftypes.FFBigInt)(gas)
	}
	log.L(ctx).Infof("Prepared transaction method=%s dataLen=%d gas=%s", method.String(), len(callData), req.Gas.Int())

	return &ffcapi.TransactionPrepareResponse{
		Gas:             req.Gas,
		TransactionData: ethtypes.HexBytes0xPrefix(callData).String(),
	}, "", nil

}

func (c *ethConnector) DeployContractPrepare(ctx context.Context, req *ffcapi.ContractDeployPrepareRequest) (*ffcapi.TransactionPrepareResponse, ffcapi.ErrorReason, error) {

	// Parse the input JSON data, to build the call data
	callData, method, err := c.prepareDeployData(ctx, &req.ContractDeployInput)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	// Build the base transaction object
	tx, err := c.buildTx(ctx, req.From, "", req.Nonce, req.Gas, req.Value, callData)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	if req.Gas == nil || req.Gas.Int().Sign() == 0 {
		// If a value for gas has not been supplied, do a gas estimate
		gas, reason, err := c.estimateGas(ctx, tx, method)
		if err != nil {
			return nil, reason, err
		}
		req.Gas = (*fftypes.FFBigInt)(gas)
	}
	log.L(ctx).Infof("Prepared transaction method=%s dataLen=%d gas=%s", method.String(), len(callData), req.Gas.Int())

	return &ffcapi.TransactionPrepareResponse{
		Gas:             req.Gas,
		TransactionData: ethtypes.HexBytes0xPrefix(callData).String(),
	}, "", nil

}

func (c *ethConnector) prepareCallData(ctx context.Context, req *ffcapi.TransactionInput) ([]byte, *abi.Entry, error) {

	// Parse the method ABI
	var method *abi.Entry
	err := json.Unmarshal(req.Method.Bytes(), &method)
	if err != nil {
		return nil, nil, i18n.NewError(ctx, msgs.MsgUnmarshalABIFail, err)
	}

	// Parse the params into the standard semantics of Go JSON unmarshalling, with []interface{}
	ethParams := make([]interface{}, len(req.Params))
	for i, p := range req.Params {
		if p != nil {
			err := json.Unmarshal([]byte(*p), &ethParams[i])
			if err != nil {
				return nil, nil, i18n.NewError(ctx, msgs.MsgUnmarshalParamFail, i, err)
			}
		}
	}

	// Match the parameters to the ABI call data for the method.
	// Note the FireFly ABI decoding package handles formatting errors / translation etc.
	var callData []byte
	paramValues, err := method.Inputs.ParseExternalDataCtx(ctx, ethParams)
	if err == nil {
		callData, err = method.EncodeCallDataCtx(ctx, paramValues)
	}
	if err != nil {
		return nil, nil, err
	}

	return callData, method, err
}

func (c *ethConnector) prepareDeployData(ctx context.Context, req *ffcapi.ContractDeployInput) ([]byte, *abi.Entry, error) {
	// Parse the bytecode as a hex string, or fallback to Base64
	var bytecodeString string
	if err := req.Bytecode.Unmarshal(ctx, &bytecodeString); err != nil {
		return nil, nil, i18n.NewError(ctx, msgs.MsgDecodeBytecodeFailed)
	}
	bytecode, err := hex.DecodeString(strings.TrimPrefix(bytecodeString, "0x"))
	if err != nil {
		bytecode, err = base64.StdEncoding.DecodeString(bytecodeString)
		if err != nil {
			return nil, nil, i18n.NewError(ctx, msgs.MsgDecodeBytecodeFailed)
		}
	}

	// Parse the ABI
	var a *abi.ABI
	err = json.Unmarshal(req.ABI.Bytes(), &a)
	if err != nil {
		return nil, nil, i18n.NewError(ctx, msgs.MsgUnmarshalABIFail, err)
	}

	// Find the constructor in the ABI
	method := a.Constructor()
	if method == nil {
		// Constructors are optional, so if there is none, simply return the bytecode as the calldata
		return bytecode, nil, nil
	}

	// Parse the params into the standard semantics of Go JSON unmarshalling, with []interface{}
	ethParams := make([]interface{}, len(req.Params))
	for i, p := range req.Params {
		if p != nil {
			err := json.Unmarshal([]byte(*p), &ethParams[i])
			if err != nil {
				return nil, nil, i18n.NewError(ctx, msgs.MsgUnmarshalParamFail, i, err)
			}
		}
	}

	// Match the parameters to the ABI call data for the method.
	// Note the FireFly ABI decoding package handles formatting errors / translation etc.
	var callData []byte
	paramValues, err := method.Inputs.ParseExternalDataCtx(ctx, ethParams)
	if err != nil {
		return nil, nil, err
	}
	callData, err = paramValues.EncodeABIData()
	if err != nil {
		return nil, nil, err
	}

	// Concatenate bytecode and constructor args for deployment transaction
	callData = append(bytecode, callData...)

	return callData, method, err
}

func (c *ethConnector) buildTx(ctx context.Context, fromString, toString string, nonce, gas, value *fftypes.FFBigInt, data []byte) (tx *ethsigner.Transaction, err error) {
	tx = &ethsigner.Transaction{
		Nonce:    (*ethtypes.HexInteger)(nonce),
		GasLimit: (*ethtypes.HexInteger)(gas),
		Value:    (*ethtypes.HexInteger)(value),
		Data:     data,
	}

	// Parse the from address (if set)
	from, err := ethtypes.NewAddress(fromString)
	if err != nil {
		return nil, i18n.NewError(ctx, msgs.MsgInvalidFromAddress, fromString, err)
	}
	tx.From = json.RawMessage(fmt.Sprintf(`"%s"`, from))

	// Parse the to address (if set)
	var to *ethtypes.Address0xHex
	if toString != "" {
		to, err = ethtypes.NewAddress(toString)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgInvalidToAddress, toString, err)
		}
		tx.To = to
	}

	return tx, nil

}
